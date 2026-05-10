use crate::input::Target;
use crate::probe::ScanResult;
use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub fn print_summary_counts(scanned: usize, valid: usize) {
    eprintln!("scanned={scanned} valid={valid}");
}

pub struct ResultStreamWriter(Box<csv::Writer<Box<dyn Write>>>);

impl ResultStreamWriter {
    pub fn new(output: Option<&Path>, append: bool) -> Result<Self> {
        let mut write_headers = true;
        let writer: Box<dyn Write> = match output {
            Some(path) if append => {
                let existing_len = match path.metadata() {
                    Ok(metadata) => metadata.len(),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("failed to inspect {}", path.display()));
                    }
                };
                write_headers = existing_len == 0;
                Box::new(
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .with_context(|| format!("failed to open {}", path.display()))?,
                )
            }
            Some(path) => Box::new(
                File::create(path)
                    .with_context(|| format!("failed to create {}", path.display()))?,
            ),
            None => Box::new(io::stdout()),
        };

        Ok(Self(Box::new(
            csv::WriterBuilder::new()
                .has_headers(write_headers)
                .from_writer(writer),
        )))
    }

    pub fn write_result(&mut self, result: &ScanResult) -> Result<()> {
        self.0.serialize(result)?;
        self.0.flush()?;

        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.0.flush()?;
        Ok(())
    }
}

pub struct TargetStreamWriter(Box<csv::Writer<Box<dyn Write>>>);

impl TargetStreamWriter {
    pub fn new(output: Option<&Path>) -> Result<Self> {
        let writer: Box<dyn Write> = match output {
            Some(path) => Box::new(
                File::create(path)
                    .with_context(|| format!("failed to create {}", path.display()))?,
            ),
            None => Box::new(io::stdout()),
        };

        Ok(Self(Box::new(csv::Writer::from_writer(writer))))
    }

    pub fn write_batch(&mut self, targets: &[Target]) -> Result<()> {
        for target in targets {
            self.0.serialize(target)?;
        }
        self.0.flush()?;

        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        self.0.flush()?;
        Ok(())
    }
}

pub fn write_json_value(value: &serde_json::Value, output: Option<&Path>) -> Result<()> {
    let mut writer: Box<dyn Write> = match output {
        Some(path) => Box::new(
            File::create(path).with_context(|| format!("failed to create {}", path.display()))?,
        ),
        None => Box::new(io::stdout()),
    };

    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}
