//totp generator based on a secret and unix-second based 30s counter.

use hmac::{Hmac, KeyInit, Mac};
//we use hmac here so that we can add a key, instead of just a counter
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};

fn main()
{
    let secret = "bigolplaceholder";
    let secret_bytes = secret.as_bytes();
    // need bytes for HMAC declaration
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is before Unix epoch")
        .as_secs();
    //unix seconds are time since the birth of unix
    let counter = unix_seconds / 30;
    // creates 30 second blocks for our counter
    let counter_bytes = counter.to_be_bytes();
    // we need our counter to be big-endian to satisfy rfc6238 algo

    let mut mac = Hmac::<Sha512>::new_from_slice(secret_bytes).expect("Invalid HMAC key");
    mac.update(&counter_bytes);
    //standard api format to update after declaration with a secret
    let result = mac.finalize();
    //completes HMAC computation and consumes it
    let digest = result.into_bytes();
    //removes wrapper here

    //it gets a bit confusing here, so pretty much we want to dynamically truncate (based on rfc)
    //effectively we are using an offset to extract a small number from something gigantic

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    // 0x0f is bitwise and for last 4 bits of the final byte. also finds index here
    // now it gets awkward cuz rfc says OTP = integer mod 10^10 but ours is 31 bits which is
    // smaller. So we have to pad to fill.

    let selected_bytes = &digest[offset..offset + 4];
    // here were making a rust slice from offset to right before offset + 4 of our digest
    // rfc algorithm tells us to extract 4 bytes so thats the reason for this

    let bytes: [u8; 4] = selected_bytes.try_into().expect("Expected 4 bytes");
    let password = u32::from_be_bytes(bytes);
    let truncated = password & 0x7fff_ffff;
    // really important here we need a positive 31 bit integer. This is to cover i32 and is
    // necessary to rfc6238. so we mask off the largest bit which would be the signed bit.

    println!("{truncated:010}");
    //prints our post-mask value and ensures it reaches 10 digits
}
