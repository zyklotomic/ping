### About
This was originally written for the Cloudflare Systems Internship
application. It is written in Rust and directly interfaces with
the Linux syscalls `socket()`, `sendto()`, `recv()`, etc. For reference,
as of time of writing, `uname` reports `5.2.21 #1-NixOS SMP x86_64 GNU/Linux`.

Repository location github.com/zyklotomic/ping
## Building it
```
cargo build
```
The resulting binary will be located at`./target/debug/ping`.

## Running it
```
ping 1.0.0
Ethan Tsz Hang Kiang @zyklotomic
A cute little `ping` in Rust

USAGE:
    ping [OPTIONS] <dest>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --count <count>          Stop sending after <count> many packets have been sent.
    -i, --interval <interval>    Wait <interval> seconds between sending each packet. Default is one second.
    -t <ttl>                     ttl

ARGS:
    <dest>    Target destination. Only Ipv4 supported
```
### Notes
Relevant permissions need to be set to run `ping`.

Update `sysctl` paramater `net.ipv4.ping_group_range` to include your group id (`id -g`).

```
$ id -g
1000
$ sudo sysctl -w net.ipv4.ping_group_range="0 1000"
net.ipv4.ping_group_range = 0 2000
```
To run without root, enable 'setuid' bit.
```
$ sudo chown root:root ./target/debug/ping
$ sudo chmod u+s ./target/debug/ping
$ sudo chmod g+s ./target/debug/ping
```

Directly pulled from https://echorand.me/posts/my-own-ping/ . Pulled from under **Implementation** and **Parting Notes**.
Thank you to Amit for that very helpful article with which I wouldn't have been able to write this without.

### TODO
Complete refactoring of this so that it isn't such spaghetti. Use `tokio`? Check the code comments.
