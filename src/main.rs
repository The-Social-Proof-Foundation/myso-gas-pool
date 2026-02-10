// Copyright (c) Mysten Labs, Inc.
// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use myso_gas_station::command::Command;

#[tokio::main]
async fn main() {
    let command = Command::parse();
    command.execute().await;
}
