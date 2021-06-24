use futures::prelude::*;
use irc::client::prelude::*;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), failure::Error> {
    let idle_threshold = 4 * 60 * 60;               // 4h to be considered idle
    let deadline = Duration::from_secs(15 * 60);    // 15m to reply to liveness check
    let alertchan = "###kline".to_string();
    let mut watchdog = tokio::time::interval(Duration::from_secs(5 * 60));
    let mut whois_slot = tokio::time::interval(Duration::from_secs(11));

    let config = Config {
        nickname: Some("scrutinyite".to_owned()),
        username: Some("scrutiny".to_owned()),
        server: Some("irc.libera.chat".to_owned()),
        channels: vec![alertchan.clone()],
        ..Config::default()
    };

    let mut client = Client::from_config(config).await?;
    let mut stream = client.stream()?;
    let mut on_call: Vec<String> = Vec::new();
    let mut to_whois: Vec<String> = Vec::new();
    // staff:(idletime, spotted time, tattled)
    let mut overdue: HashMap<String, (u64, Instant, bool)> = HashMap::new();

    client.identify()?;

    loop {
        tokio::select! {
            // At the start and every 5 mins, trigger a check of statsp
            _ = watchdog.tick() => {
                client.send(Command::STATS(Some("p".to_owned()), None))?;
            }

            // Every 10+1 seconds, use our new allocation of remote whois to check any unwhoised
            // staff we've found
            _ = whois_slot.tick() => {
                if to_whois.len() > 0 {
                    let staffnick = to_whois.remove(0);
                    client.send(Command::WHOIS(Some(staffnick.clone()), staffnick.clone()))?;
                }
            }

            // Message handling
            Some(message) = stream.next() => {
                //println!("{:?}", message);
                match message?.command {
                    // Handle incoming statsp requests
                    Command::Raw(numeric, mut params) if numeric == "249" => {
                        let entry = params.pop().unwrap();
                        if entry.ends_with("staff members") {
                            continue;
                        }
                        let staffnick = entry.split_whitespace()
                            .next()
                            .unwrap()
                            .to_owned();

                        // Accumulate from here to a temp stack and then use that stack to remove
                        // destaffed people in endofstats
                        on_call.push(staffnick);
                    }

                    // Identify end of statsp to generate a log
                    Command::Response(Response::RPL_ENDOFSTATS, _) => {
                        // remove anyone who is marked overdue but no longer staff here
                        overdue = remove_destaffed(overdue, &on_call);
                        println!("got end of stats: {:?}", on_call);
                        println!("currently overdue: {:?}", overdue.keys());
                        to_whois.append(&mut on_call);
                    }

                    Command::Response(Response::RPL_WHOISIDLE, mut params) => {
                        // The remove here shifts the idle time one left, from 2nd to 1st offset
                        // hence indexing `1` twice.
                        let staffnick = params.remove(1);
                        let idletime = params[1].parse::<u64>().unwrap();
                        println!("got an idletime: {} is idle {}s", staffnick, idletime);


                        // check if this staffer is in our overdue list
                        // if they arent:
                        //   and they are now over-idle:
                        //     mark them overdue
                        //     alert them
                        // if they are in the overdue list:
                        //   if their idletime has decreased: they've been active, remove them
                        //   otherwise: if our alert to them was > deadline, call the cops

                        match overdue.entry(staffnick.clone()) {
                            Vacant(entry) => {
                                if idletime > idle_threshold {
                                    if staffnick == "kline" {
                                        client.send_privmsg(&staffnick, "You're overdue, are you still alive?")?;
                                    }
                                    entry.insert((idletime, Instant::now(), false));
                                }
                            }
                            Occupied(mut entry) => {
                                let (first_idle_length, spotted, tattled) = entry.get_mut();
                                if idletime <= *first_idle_length {
                                    println!("removing {}, idletime decreased", staffnick);
                                    entry.remove();
                                } else {
                                    if spotted.elapsed() > deadline && !(*tattled) {
                                        client.send_privmsg(
                                            &alertchan,
                                            format!(
                                                "{} has been idle more than {} and didn't reply to me for {}. \
                                                They might not be around.",
                                                staffnick, secs_to_time(&idletime),
                                                secs_to_time(&spotted.elapsed().as_secs())
                                            )
                                        )?;
                                        *tattled = true;
                                    }
                                }
                            }
                        }
                    }
                    // Ignore unrecognised messages
                    _ => (),
                }
            }
        }
    }
}

fn remove_destaffed(
    overdue_list: HashMap<String, (u64, Instant, bool)>,
    on_call_list: &Vec<String>,
) -> HashMap<String, (u64, Instant, bool)> {
    return overdue_list
        .into_iter()
        .filter(|(staffer, _)| on_call_list.contains(&staffer))
        .collect();
}

fn secs_to_time(secs: &u64) -> String {
    let mut minutes = secs / 60;
    let hours = minutes / 60;
    minutes = minutes % 60;
    format!("{}h{}m", hours, minutes)
}
