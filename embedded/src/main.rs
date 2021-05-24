#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![no_std]
#![no_main]

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

use cortex_m::asm;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath, ExtendedPubKey};
use core::str::FromStr;
use hal::rcc::RccExt;
use hal::flash::FlashExt;
use hal::pwr::PwrExt;
use hal::delay::Delay;
use hal::prelude::*;
use stm32l4xx_hal::time::{MonoTimer, Instant};

// this is the allocator the application will use
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024 * 32; // in bytes

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

    // Let clock settle ?!
    delay.delay_ms(1000_u32);

    let start = timer.now();
    delay.delay_ms(123_u32);
    hprintln!("a 123 ms task took {} ms", elapsed_ms(&timer, start)).unwrap();

    hprintln!("heap size {}", HEAP_SIZE).unwrap();

    unsafe { ALLOCATOR.init(cortex_m_rt::heap_start() as usize, HEAP_SIZE) }

    let size = Secp256k1::preallocate_size();
    hprintln!("secp buf size {}", size*16).unwrap();

    // Load a private key
    let raw = "L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D";
    let pk = PrivateKey::from_wif(raw).unwrap();
    hprintln!("Seed WIF: {}", pk).unwrap();

    let mut buf_ful = vec![AlignedType::zeroed(); size];
    let secp = Secp256k1::preallocated_new(&mut buf_ful).unwrap();

    // Derive address
    let pubkey = pk.public_key(&secp);

    bench_signing(&timer, &pk, &secp, &pubkey);

    test_address(&pubkey);

    test_keys(pk, &secp);

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn elapsed_ms(timer: &MonoTimer, start: Instant) -> u64 {
    (start.elapsed() as u64) * 1000 / (timer.frequency().0 as u64)
}

fn bench_signing(timer: &MonoTimer, pk: &PrivateKey, secp: &Secp256k1<AllPreallocated>, pubkey: &PublicKey) {
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let sig = secp.sign(&msg, &pk.key);
    let start = timer.now();
    for _ in 0..100 {
        secp.sign(&msg, &pk.key);
    }
    hprintln!("signing took {} ms", elapsed_ms(timer, start)).unwrap();

    let start = timer.now();
    for _ in 0..100 {
        secp.verify(&msg, &sig, &pubkey.key).unwrap();
    }
    hprintln!("verification took {} ms", elapsed_ms(&timer, start)).unwrap();
}

fn test_keys(pk: PrivateKey, secp: &Secp256k1<AllPreallocated>) {
    let network = pk.network;
    let seed = pk.to_bytes();
    let root = ExtendedPrivKey::new_master(network, &seed).unwrap();
    hprintln!("Root key: {}", root).unwrap();

    // derive child xpub
    let path = DerivationPath::from_str("m/84h/0h/0h").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    hprintln!("Child at {}: {}", path, child).unwrap();
    let xpub = ExtendedPubKey::from_private(&secp, &child);
    hprintln!("Public key at {}: {}", path, xpub).unwrap();
}

fn test_address(pubkey: &PublicKey) {
    let address = Address::p2wpkh(&pubkey, Network::Bitcoin).unwrap();
    hprintln!("Address: {}", address).unwrap();

    assert_eq!(address.to_string(), "bc1qpx9t9pzzl4qsydmhyt6ctrxxjd4ep549np9993".to_string());
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
