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
use hal::rtc::{Rtc, RtcConfig, RtcClockSource};
use hal::rcc::{RccExt, CrystalBypass, ClockSecuritySystem};
use hal::flash::FlashExt;
use hal::pwr::PwrExt;
use hal::delay::Delay;
use hal::datetime::{Time, U32Ext, Date};
use hal::prelude::*;

// this is the allocator the application will use
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

const HEAP_SIZE: usize = 1024 * 32; // in bytes

fn get_millis(rtc: &Rtc) -> u32 {
    let (_date, time) = rtc.get_date_time();
    time.micros / 1000 + time.seconds * 1000 + time.minutes * 60 * 1000
}

#[entry]
fn main() -> ! {
    let cp = cortex_m::Peripherals::take().unwrap();
    let dp = hal::stm32::Peripherals::take().unwrap();

    let mut flash = dp.FLASH.constrain();
    let mut rcc = dp.RCC.constrain();
    let mut pwr = dp.PWR.constrain(&mut rcc.apb1r1);

    // Try a different clock configuration
    let clocks = rcc
        .cfgr
        .lse(CrystalBypass::Disable, ClockSecuritySystem::Disable)
        .freeze(&mut flash.acr, &mut pwr);

    let mut timer = Delay::new(cp.SYST, clocks);

    let mut rtc = Rtc::rtc(
        dp.RTC,
        &mut rcc.apb1r1,
        &mut rcc.bdcr,
        &mut pwr.cr1,
        RtcConfig::default().clock_config(RtcClockSource::LSE),
    );

    let time = Time::new(0.hours(), 0.minutes(), 0.seconds(), 0.micros(), false);
    let date = Date::new(1.day(), 1.date(), 1.month(), 2018.year());

    rtc.set_date_time(date, time);

    // Let clock settle ?!
    timer.delay_ms(1000_u32);

    let start = get_millis(&rtc);
    timer.delay_ms(666_u32);
    let end = get_millis(&rtc);
    hprintln!("took {} ms", end - start).unwrap();

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

    bench_signing(&mut rtc, &pk, &secp, &pubkey);

    test_address(&pubkey);

    test_keys(pk, &secp);

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}

fn bench_signing(rtc: &mut Rtc, pk: &PrivateKey, secp: &Secp256k1<AllPreallocated>, pubkey: &PublicKey) {
    let msg = Message::from_slice(&[0x33; 32]).unwrap();
    let sig = secp.sign(&msg, &pk.key);
    let start = get_millis(&rtc);
    for _ in 0..100 {
        secp.sign(&msg, &pk.key);
    }
    let end = get_millis(&rtc);
    hprintln!("signing took {} ms", end - start).unwrap();

    let start = get_millis(&rtc);
    for _ in 0..100 {
        secp.verify(&msg, &sig, &pubkey.key).unwrap();
    }
    let end = get_millis(&rtc);
    hprintln!("verification took {} ms", end - start).unwrap();
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
