use base64::Engine;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, Sample, SampleFormat, SizedSample, Stream, StreamConfig};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::protocol::{ClientMessage, MAX_VOICE_PACKET_BYTES, VOICE_SAMPLE_RATE};

const FRAMES_PER_SECOND: usize = 50;
const OPUS_FRAME_SAMPLES: usize = VOICE_SAMPLE_RATE as usize / FRAMES_PER_SECOND;
const OPUS_MAX_DECODED_SAMPLES: usize = OPUS_FRAME_SAMPLES;
const MAX_ENCODED_FRAME_SIZE: usize = 1_700;
const MAX_REMOTE_SPEAKERS: usize = 32;

struct PlaybackState {
    queues: HashMap<String, VecDeque<f32>>,
    decoders: HashMap<String, opus::Decoder>,
}

type PlaybackQueues = Arc<Mutex<PlaybackState>>;
type VoiceTarget = Arc<Mutex<(String, String)>>;

pub struct VoiceChat {
    _input_stream: Stream,
    _output_stream: Stream,
    output_sample_rate: u32,
    control_sender: mpsc::UnboundedSender<ClientMessage>,
    target: VoiceTarget,
    playback: PlaybackQueues,
}

impl VoiceChat {
    pub fn start(
        server_id: String,
        channel_id: String,
        control_sender: mpsc::UnboundedSender<ClientMessage>,
        audio_sender: mpsc::Sender<ClientMessage>,
    ) -> Result<Self, String> {
        let host = cpal::default_host();
        let input_device = host
            .default_input_device()
            .ok_or_else(|| "No microphone is available.".to_string())?;
        let output_device = host
            .default_output_device()
            .ok_or_else(|| "No speaker or headphone output is available.".to_string())?;
        let input_supported = input_device
            .default_input_config()
            .map_err(|error| format!("Could not configure the microphone: {error}"))?;
        let output_supported = output_device
            .default_output_config()
            .map_err(|error| format!("Could not configure audio output: {error}"))?;
        let input_format = input_supported.sample_format();
        let output_format = output_supported.sample_format();
        let input_config: StreamConfig = input_supported.into();
        let output_config: StreamConfig = output_supported.into();
        let output_sample_rate = output_config.sample_rate;
        let target = Arc::new(Mutex::new((server_id.clone(), channel_id.clone())));
        let playback = Arc::new(Mutex::new(PlaybackState {
            queues: HashMap::new(),
            decoders: HashMap::new(),
        }));

        let input_stream = build_input_stream(
            &input_device,
            input_config,
            input_format,
            target.clone(),
            audio_sender,
        )?;
        let output_stream = build_output_stream(
            &output_device,
            output_config,
            output_format,
            playback.clone(),
        )?;
        input_stream
            .play()
            .map_err(|error| format!("Could not start the microphone: {error}"))?;
        output_stream
            .play()
            .map_err(|error| format!("Could not start audio playback: {error}"))?;
        let _ = control_sender.send(ClientMessage::SelectChannel {
            server_id: server_id.clone(),
            channel_id: channel_id.clone(),
        });

        Ok(Self {
            _input_stream: input_stream,
            _output_stream: output_stream,
            output_sample_rate,
            control_sender,
            target,
            playback,
        })
    }

    pub fn retarget(&self, server_id: String, channel_id: String) {
        let _ = self.control_sender.send(ClientMessage::SelectChannel {
            server_id: server_id.clone(),
            channel_id: channel_id.clone(),
        });
        *self.target.lock().unwrap() = (server_id, channel_id);
    }

    pub fn push_remote_frame(
        &self,
        author: &str,
        sample_rate: u32,
        encoded_audio: &str,
    ) -> Result<(), String> {
        if sample_rate != VOICE_SAMPLE_RATE || encoded_audio.len() > MAX_ENCODED_FRAME_SIZE {
            return Err("Voice frame is outside the supported limits.".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded_audio)
            .map_err(|_| "Voice frame is not valid base64.".to_string())?;
        if bytes.is_empty() || bytes.len() > MAX_VOICE_PACKET_BYTES {
            return Err("Voice frame has an invalid Opus packet size.".into());
        }

        let mut state = self.playback.lock().unwrap();
        if !state.decoders.contains_key(author) && state.decoders.len() >= MAX_REMOTE_SPEAKERS {
            return Err("Too many remote speakers are active.".into());
        }
        if !state.decoders.contains_key(author) {
            let decoder = opus::Decoder::new(VOICE_SAMPLE_RATE, opus::Channels::Mono)
                .map_err(|error| format!("Could not initialize Opus decoder: {error}"))?;
            state.decoders.insert(author.to_string(), decoder);
        }
        let mut source = vec![0.0; OPUS_MAX_DECODED_SAMPLES];
        let decoded_samples = state
            .decoders
            .get_mut(author)
            .expect("decoder was inserted")
            .decode_float(&bytes, &mut source, false)
            .map_err(|error| format!("Invalid Opus voice frame: {error}"))?;
        if decoded_samples == 0 {
            return Ok(());
        }
        source.truncate(decoded_samples);

        let destination_len =
            ((source.len() as u64 * self.output_sample_rate as u64) / sample_rate as u64) as usize;
        if destination_len == 0 {
            return Ok(());
        }
        let mut resampled = Vec::with_capacity(destination_len);
        for index in 0..destination_len {
            let position = index as f32 * sample_rate as f32 / self.output_sample_rate as f32;
            let left = (position as usize).min(source.len() - 1);
            let right = (left + 1).min(source.len() - 1);
            let fraction = position.fract();
            resampled.push(source[left] * (1.0 - fraction) + source[right] * fraction);
        }

        state.queues.retain(|_, queue| !queue.is_empty());
        let queue = state.queues.entry(author.to_string()).or_default();
        let max_queue_len = self.output_sample_rate as usize;
        if queue.len() + resampled.len() > max_queue_len {
            let discard = (queue.len() + resampled.len() - max_queue_len).min(queue.len());
            queue.drain(..discard);
        }
        queue.extend(resampled);
        Ok(())
    }
}

impl Drop for VoiceChat {
    fn drop(&mut self) {
        let _ = self.control_sender.send(ClientMessage::LeaveVoice);
    }
}

fn build_input_stream(
    device: &cpal::Device,
    config: StreamConfig,
    format: SampleFormat,
    target: VoiceTarget,
    sender: mpsc::Sender<ClientMessage>,
) -> Result<Stream, String> {
    macro_rules! build {
        ($sample:ty) => {
            build_capture_stream::<$sample>(device, config, target, sender)
        };
    }

    let stream = match format {
        SampleFormat::I8 => build!(i8),
        SampleFormat::U8 => build!(u8),
        SampleFormat::I16 => build!(i16),
        SampleFormat::U16 => build!(u16),
        SampleFormat::I24 => build!(cpal::I24),
        SampleFormat::U24 => build!(cpal::U24),
        SampleFormat::I32 => build!(i32),
        SampleFormat::U32 => build!(u32),
        SampleFormat::I64 => build!(i64),
        SampleFormat::U64 => build!(u64),
        SampleFormat::F32 => build!(f32),
        SampleFormat::F64 => build!(f64),
        _ => return Err(format!("Microphone format {format} is not supported.")),
    }
    .map_err(|error| format!("Could not open the microphone: {error}"))?;
    Ok(stream)
}

fn build_capture_stream<T>(
    device: &cpal::Device,
    config: StreamConfig,
    target: VoiceTarget,
    sender: mpsc::Sender<ClientMessage>,
) -> Result<Stream, String>
where
    T: SizedSample + Sample + Copy,
    f32: FromSample<T>,
{
    let channels = config.channels as usize;
    let sample_rate = config.sample_rate;
    let mut encoder = opus::Encoder::new(
        VOICE_SAMPLE_RATE,
        opus::Channels::Mono,
        opus::Application::Voip,
    )
    .map_err(|error| format!("Could not initialize Opus encoder: {error}"))?;
    encoder
        .set_bitrate(opus::Bitrate::Bits(24_000))
        .map_err(|error| format!("Could not configure Opus encoder: {error}"))?;
    encoder
        .set_complexity(5)
        .map_err(|error| format!("Could not configure Opus encoder: {error}"))?;
    let mut resample_phase = 0_u64;
    let mut pending = Vec::<f32>::with_capacity(OPUS_FRAME_SAMPLES * 2);
    device
        .build_input_stream(
            config,
            move |data: &[T], _| {
                for frame in data.chunks(channels) {
                    let mono = frame
                        .iter()
                        .map(|sample| f32::from_sample(*sample))
                        .sum::<f32>()
                        / channels as f32;
                    resample_phase += VOICE_SAMPLE_RATE as u64;
                    while resample_phase >= sample_rate as u64 {
                        resample_phase -= sample_rate as u64;
                        pending.push(mono.clamp(-1.0, 1.0));
                    }
                }
                while pending.len() >= OPUS_FRAME_SAMPLES {
                    let samples: Vec<_> = pending.drain(..OPUS_FRAME_SAMPLES).collect();
                    let mut packet = vec![0_u8; MAX_VOICE_PACKET_BYTES];
                    let Ok(packet_len) = encoder.encode_float(&samples, &mut packet) else {
                        continue;
                    };
                    packet.truncate(packet_len);
                    let (server_id, channel_id) = target.lock().unwrap().clone();
                    let audio = base64::engine::general_purpose::STANDARD.encode(packet);
                    let _ = sender.try_send(ClientMessage::VoiceFrame {
                        server_id,
                        channel_id,
                        sample_rate: VOICE_SAMPLE_RATE,
                        audio,
                    });
                }
            },
            |error| eprintln!("microphone stream error: {error}"),
            None,
        )
        .map_err(|error| error.to_string())
}

fn build_output_stream(
    device: &cpal::Device,
    config: StreamConfig,
    format: SampleFormat,
    playback: PlaybackQueues,
) -> Result<Stream, String> {
    macro_rules! build {
        ($sample:ty) => {
            build_playback_stream::<$sample>(device, config, playback)
        };
    }

    let stream = match format {
        SampleFormat::I8 => build!(i8),
        SampleFormat::U8 => build!(u8),
        SampleFormat::I16 => build!(i16),
        SampleFormat::U16 => build!(u16),
        SampleFormat::I24 => build!(cpal::I24),
        SampleFormat::U24 => build!(cpal::U24),
        SampleFormat::I32 => build!(i32),
        SampleFormat::U32 => build!(u32),
        SampleFormat::I64 => build!(i64),
        SampleFormat::U64 => build!(u64),
        SampleFormat::F32 => build!(f32),
        SampleFormat::F64 => build!(f64),
        _ => return Err(format!("Speaker format {format} is not supported.")),
    }
    .map_err(|error| format!("Could not open audio output: {error}"))?;
    Ok(stream)
}

fn build_playback_stream<T>(
    device: &cpal::Device,
    config: StreamConfig,
    playback: PlaybackQueues,
) -> Result<Stream, cpal::Error>
where
    T: SizedSample + Sample + FromSample<f32> + Copy,
{
    let channels = config.channels as usize;
    device.build_output_stream(
        config,
        move |data: &mut [T], _| {
            if let Ok(mut state) = playback.try_lock() {
                for frame in data.chunks_mut(channels) {
                    let active_speakers = state
                        .queues
                        .values()
                        .filter(|queue| !queue.is_empty())
                        .count();
                    let mixed = state
                        .queues
                        .values_mut()
                        .filter_map(VecDeque::pop_front)
                        .sum::<f32>()
                        / (active_speakers.max(1) as f32).sqrt();
                    let sample = T::from_sample(mixed.clamp(-1.0, 1.0));
                    frame.fill(sample);
                }
            } else {
                data.fill(T::EQUILIBRIUM);
            }
        },
        |error| eprintln!("speaker stream error: {error}"),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::{OPUS_FRAME_SAMPLES, VOICE_SAMPLE_RATE};

    #[test]
    fn opus_voice_frame_is_smaller_than_pcm_and_decodes() {
        let input: Vec<_> = (0..OPUS_FRAME_SAMPLES)
            .map(|index| {
                let phase = index as f32 * std::f32::consts::TAU * 440.0 / VOICE_SAMPLE_RATE as f32;
                phase.sin() * 0.4
            })
            .collect();
        let mut encoder = opus::Encoder::new(
            VOICE_SAMPLE_RATE,
            opus::Channels::Mono,
            opus::Application::Voip,
        )
        .unwrap();
        encoder.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        let mut packet = vec![0; super::MAX_VOICE_PACKET_BYTES];
        let packet_len = encoder.encode_float(&input, &mut packet).unwrap();
        assert!(packet_len > 0);
        assert!(packet_len < input.len() * std::mem::size_of::<i16>());

        let mut decoder = opus::Decoder::new(VOICE_SAMPLE_RATE, opus::Channels::Mono).unwrap();
        let mut decoded = vec![0.0; OPUS_FRAME_SAMPLES];
        let decoded_samples = decoder
            .decode_float(&packet[..packet_len], &mut decoded, false)
            .unwrap();
        assert_eq!(decoded_samples, OPUS_FRAME_SAMPLES);
        assert!(decoded.iter().all(|sample| sample.is_finite()));
    }
}
