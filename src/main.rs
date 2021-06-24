use irc::client::prelude::*;
use futures::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    let config = Config {
        nickname: Some("scrutinyite".to_owned()),
        username: Some("scrutiny".to_owned()),
        server: Some("irc.libera.chat".to_owned()),
        channels: vec!["###kline".to_owned()],
        ..Config::default()
    };
    
    let mut client = Client::from_config(config).await?;
    client.identify()?;

    let mut stream = client.stream()?;
    let mut watchdog = tokio::time::interval(Duration::from_secs(5 * 60));
    let mut to_check = Vec::new();
    
    loop {
        tokio::select! {
            // At the start and every 5 mins, trigger a check of statsp
            _ = watchdog.tick() => {
                to_check.clear();
                client.send(Command::STATS(Some("p".to_owned()), None))?;
            }

            // Message handling
            Some(message) = stream.next() => {
                match message?.command {
                    // Handle incoming statsp requests
                    Command::Raw(numeric, mut params) if numeric == "249" => {
                        let staffer = params.pop().unwrap();
                        if staffer.ends_with("staff members") {
                            continue;
                        }
                        to_check.push(staffer);
                    }

                    // Identify end of statsp to generate a log
                    Command::Response(Response::RPL_ENDOFSTATS, _) => {
                        println!("got end of stats: {:?}", to_check);
                    }

                    // Ignore unrecognised messages
                    _ => (),
                }
            }

        }
    }
}
