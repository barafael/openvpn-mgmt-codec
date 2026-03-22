//! Rolling throughput chart using `plotters` + `plotters-iced2`.

use std::collections::VecDeque;

use iced::{Element, Length};
use plotters::prelude::*;
use plotters_iced2::{Chart, ChartWidget};

use crate::message::Message;

// -------------------------------------------------------------------
// Throughput history
// -------------------------------------------------------------------

/// A single throughput sample (bytes per second in each direction).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sample {
    pub in_bps: f64,
    pub out_bps: f64,
}

const MAX_SAMPLES: usize = 60;

/// Rolling ring buffer of throughput samples.
#[derive(Debug, Clone)]
pub(crate) struct ThroughputHistory {
    samples: VecDeque<Sample>,
    /// Previous cumulative byte counts — used to compute the delta.
    prev_in: u64,
    prev_out: u64,
    /// Whether we have received at least one reading (the first one is
    /// used to seed `prev_*` and doesn't produce a sample).
    seeded: bool,
}

impl Default for ThroughputHistory {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
            prev_in: 0,
            prev_out: 0,
            seeded: false,
        }
    }
}

impl ThroughputHistory {
    /// Feed a new cumulative byte-count reading.
    ///
    /// `interval` is the configured bytecount interval in seconds (used to
    /// convert the delta into bytes/sec).
    pub(crate) fn push(&mut self, bytes_in: u64, bytes_out: u64, interval_secs: u32) {
        if !self.seeded {
            self.prev_in = bytes_in;
            self.prev_out = bytes_out;
            self.seeded = true;
            return;
        }

        let dt = interval_secs.max(1) as f64;
        let sample = Sample {
            in_bps: bytes_in.saturating_sub(self.prev_in) as f64 / dt,
            out_bps: bytes_out.saturating_sub(self.prev_out) as f64 / dt,
        };
        self.prev_in = bytes_in;
        self.prev_out = bytes_out;

        if self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub(crate) fn samples(&self) -> &VecDeque<Sample> {
        &self.samples
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// Chart implementation
// -------------------------------------------------------------------

/// Wrapper that implements `plotters_iced2::Chart` for the throughput data.
pub(crate) struct ThroughputChart<'a> {
    history: &'a ThroughputHistory,
}

impl<'a> ThroughputChart<'a> {
    pub(crate) fn new(history: &'a ThroughputHistory) -> Self {
        Self { history }
    }
}

impl Chart<Message> for ThroughputChart<'_> {
    type State = ();

    fn build_chart<DB: DrawingBackend>(&self, _state: &Self::State, _builder: ChartBuilder<DB>) {
        // We use draw_chart for full control.
    }

    fn draw_chart<DB: DrawingBackend>(
        &self,
        _state: &Self::State,
        root: DrawingArea<DB, plotters::coord::Shift>,
    ) {
        // Gruvbox colours
        let bg = RGBColor(40, 40, 40);
        let fg_muted = RGBColor(146, 131, 116);
        let green = RGBColor(184, 187, 38);
        let blue = RGBColor(131, 165, 152);

        root.fill(&bg).ok();

        let samples = self.history.samples();
        let n = samples.len();

        // Determine y-axis max (auto-scale with a floor).
        let y_max = samples
            .iter()
            .map(|s| s.in_bps.max(s.out_bps))
            .fold(1024.0_f64, f64::max)
            * 1.15;

        let x_range = 0.0..(MAX_SAMPLES as f64);
        let y_range = 0.0..y_max;

        let mut chart = ChartBuilder::on(&root)
            .margin(4)
            .margin_right(8)
            .x_label_area_size(0)
            .y_label_area_size(42)
            .build_cartesian_2d(x_range, y_range);

        if let Ok(ref mut chart) = chart {
            chart
                .configure_mesh()
                .disable_x_mesh()
                .disable_x_axis()
                .y_labels(2)
                .y_label_formatter(&|v| format_rate(*v))
                .label_style(TextStyle::from(("monospace", 10).into_font()).color(&fg_muted))
                .axis_style(fg_muted)
                .light_line_style(RGBColor(60, 56, 54))
                .draw()
                .ok();

            // Offset so the latest sample is at the right edge.
            let offset = MAX_SAMPLES.saturating_sub(n) as f64;

            // Download (in) — green
            chart
                .draw_series(LineSeries::new(
                    samples
                        .iter()
                        .enumerate()
                        .map(|(i, s)| (i as f64 + offset, s.in_bps)),
                    green.stroke_width(2),
                ))
                .ok();

            // Upload (out) — blue
            chart
                .draw_series(LineSeries::new(
                    samples
                        .iter()
                        .enumerate()
                        .map(|(i, s)| (i as f64 + offset, s.out_bps)),
                    blue.stroke_width(2),
                ))
                .ok();
        }
    }
}

/// Format bytes/sec in a compact human-readable form for axis labels.
fn format_rate(bps: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;

    if bps >= MIB {
        format!("{:.0}M", bps / MIB)
    } else if bps >= KIB {
        format!("{:.0}K", bps / KIB)
    } else {
        format!("{:.0}B", bps)
    }
}

// -------------------------------------------------------------------
// View helper
// -------------------------------------------------------------------

/// Create a chart widget element for the throughput history with a custom height.
pub(crate) fn throughput_chart_sized(
    history: &ThroughputHistory,
    height: f32,
) -> Element<'_, Message> {
    ChartWidget::new(ThroughputChart::new(history))
        .width(Length::Fill)
        .height(Length::Fixed(height))
        .into()
}
