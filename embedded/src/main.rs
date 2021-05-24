#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![no_std]
#![no_main]
#![allow(unused_variables)]

extern crate alloc;
extern crate bitcoin;

use stm32l4xx_hal as hal;

use alloc::string::ToString;
use alloc::vec;
use core::alloc::Layout;
use core::panic::PanicInfo;

use alloc_cortex_m::CortexMHeap;
// use panic_halt as _;
use bitcoin::{Address, Network, PrivateKey, PublicKey};
use bitcoin::secp256k1::ffi::types::AlignedType;
use bitcoin::secp256k1::{Secp256k1, Message, AllPreallocated};

#[allow(unused_imports)]
use cortex_m::{asm, itm, iprintln};
use cortex_m_rt::entry;
#[allow(unused_imports)]
use cortex_m_semihosting::{debug, hprintln, export::{hstdout_str, hstdout_fmt}};
use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath, ExtendedPubKey};
use core::str::FromStr;
use hal::rcc::RccExt;
use hal::flash::FlashExt;
use hal::pwr::PwrExt;
use hal::delay::Delay;
use hal::prelude::*;
use stm32l4xx_hal::time::{MonoTimer, Instant};
use cortex_m::peripheral::itm::Stim;

// NOTE: various to_string calls are to speed up semihosting prints

// this is the allocator the application will use
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024 * 32; // in bytes
const LOOPS: u64 = 100;

const USE_ITM: bool = true;

macro_rules! println {
    ($channel:expr, $fmt:expr) => {
        if USE_ITM { itm::write_str($channel, concat!($fmt, "\n")) }
        else { hstdout_str(concat!($fmt, "\n")).unwrap() }
    };
    ($channel:expr, $fmt:expr, $($arg:tt)*) => {
        if USE_ITM { itm::write_fmt($channel, format_args!(concat!($fmt, "\n"), $($arg)*))}
        else { hstdout_fmt(format_args!(concat!($fmt, "\n"), $($arg)*)).unwrap() }
    };
}


#[entry]
fn main() -> ! {
    let cp = cortex_m::Peripherals::take().unwrap();
    let dp = hal::stm32::Peripherals::take().unwrap();

    let mut flash = dp.FLASH.constrain();
    let mut rcc = dp.RCC.constrain();
    let mut pwr = dp.PWR.constrain(&mut rcc.apb1r1);
    let dwt = cp.DWT;

    let clocks = rcc.cfgr.freeze(&mut flash.acr, &mut pwr);

    let timer = MonoTimer::new(dwt, clocks);
    let mut delay = Delay::new(cp.SYST, clocks);
    let mut itm = cp.ITM;
    let stim = &mut itm.stim[0];

    // Let clock settle ?!
    delay.delay_ms(1000_u32);

    let start = timer.now();
    delay.delay_ms(123_u32);
    println!(stim, "a 123 ms task took {} ms, freq {}", elapsed_ms(&timer, start), clocks.sysclk().0);

    println!(stim, "heap size {}", HEAP_SIZE);

    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let size = Secp256k1::preallocate_size();
    println!(stim, "secp buf size {}", size*16);

    // Load a private key
    let raw = "L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D";
    let pk = PrivateKey::from_wif(raw).unwrap();
    println!(stim, "Seed WIF: {}", pk);

    let mut buf_ful = vec![AlignedType::zeroed(); size];
    let secp = Secp256k1::preallocated_new(&mut buf_ful).unwrap();

    // Derive address
    let pubkey = pk.public_key(&secp);

    bench_signing(stim, &timer, &pk, &secp, &pubkey);

    test_address(stim, &pubkey);

    test_keys(stim, pk, &secp);

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn elapsed_ms(timer: &MonoTimer, start: Instant) -> u64 {
    (start.elapsed() as u64) * 1000 / (timer.frequency().0 as u64)
}

fn bench_signing(stim: &mut Stim, timer: &MonoTimer, pk: &PrivateKey, secp: &Secp256k1<AllPreallocated>, pubkey: &PublicKey) {
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let sig = secp.sign(&msg, &pk.key);
    let start = timer.now();
    for _ in 0..LOOPS {
        secp.sign(&msg, &pk.key);
    }
    println!(stim, "signing took {} ms", elapsed_ms(timer, start) / LOOPS);

    let start = timer.now();
    for _ in 0..LOOPS {
        secp.verify(&msg, &sig, &pubkey.key).unwrap();
    }
    println!(stim, "verification took {} ms", elapsed_ms(&timer, start) / LOOPS);
}

fn test_keys(stim: &mut Stim, pk: PrivateKey, secp: &Secp256k1<AllPreallocated>) {
    let network = pk.network;
    let seed = pk.to_bytes();
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
    println!(stim, "Root key: {}", root);

    // derive child xpub
    let path = DerivationPath::from_str("m/84h/0h/0h").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    println!(stim, "Child at {}: {}", path, child);
    let xpub = ExtendedPubKey::from_private(&secp, &child);
    println!(stim, "Public key at {}: {}", path, xpub);
}

fn test_address(stim: &mut Stim, pubkey: &PublicKey) {
    let address = Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap();
    println!(stim, "Address: {}", address);

    assert_eq!(address.to_string(), "bc1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549np9993");
}

// define what happens in an Out Of Memory (OOM) condition
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    hprintln!("alloc error").unwrap();
    debug::exit(debug::EXIT_FAILURE);
    asm::bkpt();

    loop {}
}

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    hprintln!("panic {:?}", info.message()).unwrap();
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}
