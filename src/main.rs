use clap::{Parser, Subcommand};
use std::fs;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

#[derive(Parser)]
#[command(name = "netool")]
#[command(about = "Async network operations tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform DNS operations
    #[command(arg_required_else_help = true)]
    Dns {
        /// Operation to perform
        #[arg(short, long, value_parser = ["resolve", "reverse"])]
        operation: String,

        /// Target: single IP/domain or path to file
        #[arg(short, long)]
        target: String,
    },
    /// Perform ping operations
    Ping {
        /// Target: single IP or path to file
        #[arg(short, long)]
        target: String,

        /// Number of ping attempts
        #[arg(short, long, default_value = "4")]
        count: u32,
    },
    /// Perform HTTP GET requests
    Get {
        /// Target: single URL or path to file
        #[arg(short, long)]
        target: String,

        /// Request timeout in seconds
        #[arg(short = 'o', long, default_value = "10")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dns { operation, target } => {
            handle_dns(operation, target).await;
        }
        Commands::Ping { target, count } => {
            handle_ping(target, count).await;
        }
        Commands::Get { target, timeout: timeout_secs } => {
            handle_get(target, timeout_secs).await;
        }
    }
}

async fn handle_dns(operation: String, target: String) {
    let targets = read_targets(&target);
    
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let mut handles = vec![];

    for t in targets {
        let resolver = resolver.clone();
        let op = operation.clone();
        
        let handle = tokio::spawn(async move {
            match op.as_str() {
                "resolve" => dns_resolve(&resolver, &t).await,
                "reverse" => dns_reverse(&resolver, &t).await,
                _ => println!("Unknown operation: {}", op),
            }
        });
        
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn dns_resolve(resolver: &TokioAsyncResolver, domain: &str) {
    match resolver.lookup_ip(domain).await {
        Ok(response) => {
            let ips: Vec<IpAddr> = response.iter().collect();
            println!("[+] {} -> {:?}", domain, ips);
        }
        Err(e) => {
            println!("[-] {} -> Error: {}", domain, e);
        }
    }
}

async fn dns_reverse(resolver: &TokioAsyncResolver, ip_str: &str) {
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => {
            match resolver.reverse_lookup(ip).await {
                Ok(response) => {
                    let names: Vec<String> = response.iter().map(|n| n.to_string()).collect();
                    println!("[+] {} -> {:?}", ip, names);
                }
                Err(e) => {
                    println!("[-] {} -> Error: {}", ip, e);
                }
            }
        }
        Err(e) => {
            println!("[-] Invalid IP address {}: {}", ip_str, e);
        }
    }
}

async fn handle_ping(target: String, count: u32) {
    let targets = read_targets(&target);
    let mut handles = vec![];

    for t in targets {
        let handle = tokio::spawn(async move {
            ping_target(&t, count).await;
        });
        
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn ping_target(target: &str, count: u32) {
    // Note: ICMP ping requires raw sockets (root/admin privileges)
    // This is a simplified TCP-based "ping" (connection test)
    
    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Try to resolve if it's a hostname
            match resolve_hostname(target).await {
                Some(ip) => ip,
                None => {
                    println!("[-] {} -> Failed to resolve", target);
                    return;
                }
            }
        }
    };

    let mut success = 0;
    let mut total_time = Duration::from_secs(0);

    for i in 0..count {
        let start = std::time::Instant::now();
        
        // Test connection to common port (80)
        let addr = format!("{}:80", ip);
        
        match timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => {
                let duration = start.elapsed();
                total_time += duration;
                success += 1;
                println!("[+] {} -> Reply #{}: time={:?}", ip, i + 1, duration);
            }
            Ok(Err(e)) => {
                println!("[-] {} -> Reply #{}: Connection failed - {}", ip, i + 1, e);
            }
            Err(_) => {
                println!("[-] {} -> Reply #{}: Timeout", ip, i + 1);
            }
        }
        
        if i < count - 1 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    let avg_time = if success > 0 {
        total_time / success
    } else {
        Duration::from_secs(0)
    };

    println!("\n--- {} ping statistics ---", ip);
    println!("{} packets transmitted, {} received, {:.1}% packet loss",
             count, success, ((count - success) as f64 / count as f64) * 100.0);
    if success > 0 {
        println!("Average time: {:?}", avg_time);
    }
}

async fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );
    
    match resolver.lookup_ip(hostname).await {
        Ok(response) => response.iter().next(),
        Err(_) => None,
    }
}

async fn handle_get(target: String, timeout_secs: u64) {
    let targets = read_targets(&target);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .expect("Failed to create HTTP client");

    let mut handles = vec![];

    for url in targets {
        let client = client.clone();
        
        let handle = tokio::spawn(async move {
            http_get(&client, &url).await;
        });
        
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn http_get(client: &reqwest::Client, url: &str) {
    let url_formatted = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    };

    let start = std::time::Instant::now();
    
    match client.get(&url_formatted).send().await {
        Ok(response) => {
            let duration = start.elapsed();
            let status = response.status();
            let content_length = response.content_length().unwrap_or(0);
            
            println!("[+] {} -> Status: {}, Size: {} bytes, Time: {:?}", 
                     url_formatted, status, content_length, duration);
            
            // Optionally print response headers
            // for (key, value) in response.headers() {
            //     println!("  {}: {:?}", key, value);
            // }
        }
        Err(e) => {
            let duration = start.elapsed();
            println!("[-] {} -> Error: {} (Time: {:?})", url_formatted, e, duration);
        }
    }
}

fn read_targets(target: &str) -> Vec<String> {
    // Check if target is a file path
    if let Ok(content) = fs::read_to_string(target) {
        content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect()
    } else {
        // Treat as single target
        vec![target.to_string()]
    }
}