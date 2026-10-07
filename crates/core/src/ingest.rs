//! Ingest guarantees, applied on the author's device before anything is
//! encrypted or stored:
//!
//! 1. **Validate by decoding** — the file must decode as an image with the
//!    `image` crate; extensions and MIME types are never trusted. This also
//!    blocks malformed files aimed at exploiting decoders downstream.
//! 2. **Strip EXIF and all metadata** (GPS included) — re-encoding from raw
//!    pixels carries nothing but pixels into storage.
//! 3. **Normalize** — re-encode to a standard ceiling (max 2048 px on the
//!    long edge, JPEG q85) plus a small thumbnail. This bounds per-image
//!    bytes and normalizes what every node stores.
//!
//! Only the normalized image is then encrypted, chunked, and handed to
//! iroh-blobs; the original never leaves the device.

use image::imageops::FilterType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Long-edge ceiling for published images.
pub const MAX_LONG_EDGE: u32 = 2048;
/// Long edge of feed thumbnails.
pub const THUMB_LONG_EDGE: u32 = 320;
/// JPEG quality for the published image and the thumbnail.
pub const JPEG_QUALITY: u8 = 85;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("not a decodable image (rejected before any storage)")]
    NotAnImage(#[from] image::ImageError),
    #[error("image encoding failed")]
    EncodeFailed,
}

/// The normalized output of ingest. Nothing original survives this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedImage {
    /// Re-encoded full image (EXIF-free, size-bounded).
    pub image: Vec<u8>,
    /// Small thumbnail for fast feeds.
    pub thumb: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// Validate, decode, strip metadata, resize, and re-encode.
pub fn normalize_image(bytes: &[u8]) -> Result<NormalizedImage, IngestError> {
    // Decode-or-reject: an ImageError here means the input never becomes
    // a post, whatever its extension claimed to be.
    let img = image::load_from_memory(bytes)?;

    let resized = resize_within(&img, MAX_LONG_EDGE);
    let thumb = resize_within(&resized, THUMB_LONG_EDGE);

    let mut image = Vec::new();
    resized
        .to_rgb8()
        .write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(&mut image, JPEG_QUALITY))
        .map_err(|_| IngestError::EncodeFailed)?;

    let mut thumb_bytes = Vec::new();
    thumb
        .to_rgb8()
        .write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(&mut thumb_bytes, JPEG_QUALITY))
        .map_err(|_| IngestError::EncodeFailed)?;

    Ok(NormalizedImage {
        image,
        thumb: thumb_bytes,
        width: resized.width(),
        height: resized.height(),
    })
}

/// Downscale so the long edge is at most `max`, never upscale.
fn resize_within(img: &image::DynamicImage, max: u32) -> image::DynamicImage {
    let (w, h) = (img.width(), img.height());
    if w <= max && h <= max {
        return img.clone();
    }
    let scale = if w >= h {
        max as f64 / w as f64
    } else {
        max as f64 / h as f64
    };
    let nw = ((w as f64 * scale).round() as u32).max(1);
    let nh = ((h as f64 * scale).round() as u32).max(1);
    img.resize_exact(nw, nh, FilterType::Lanczos3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gradient_png(w: u32, h: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let img = image::DynamicImage::new_rgb8(w, h);
        img.to_rgb8()
            .write_with_encoder(image::codecs::png::PngEncoder::new(&mut buf))
            .unwrap();
        buf
    }

    #[test]
    fn normalizes_and_downscales() {
        let png = gradient_png(4096, 2048);
        let norm = normalize_image(&png).unwrap();
        assert!(norm.width <= MAX_LONG_EDGE);
        assert_eq!(norm.width, 2048); // long edge clamped
        assert!(norm.height <= 1024 + 1); // aspect preserved
        // Encoded JPEG, not the original PNG.
        assert_eq!(norm.image[0], 0xFF);
        assert_eq!(norm.image[1], 0xD8);
    }

    #[test]
    fn never_upscales() {
        let png = gradient_png(100, 80);
        let norm = normalize_image(&png).unwrap();
        assert_eq!(norm.width, 100);
        assert_eq!(norm.height, 80);
    }

    #[test]
    fn rejects_non_images() {
        assert!(normalize_image(b"definitely not an image").is_err());
        assert!(normalize_image(&[0xFF, 0xD8, 0xFF, 0x00, 0x02, 0x00]).is_err()); // truncated jpeg header
    }

    #[test]
    fn thumbnail_is_small() {
        let png = gradient_png(1600, 1200);
        let norm = normalize_image(&png).unwrap();
        let t = image::load_from_memory(&norm.thumb).unwrap();
        assert!(t.width().max(t.height()) <= THUMB_LONG_EDGE);
    }
}