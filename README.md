## Sediment - Active Directory Password Filter (WIP)
Sediment is an Active Directory [password filter](https://docs.microsoft.com/en-us/windows/desktop/secmgmt/password-filters) built in Rust. Using modern data structures, it is able to provide maximum performance
with zero compromise to security. Passwords are handled using [`zeroize`](https://crates.io/crates/zeroize), guaranteeing that the memory behind will be cleared when no longer needed. Event logs are generated for
transparency into rejections, without logging the plaintext password being used.

## Setup
Once this project is finished, an MSI installer will be provided which will include the password filter DLL, and an optional CLI available for managing the compromised and banned password lists. It will also create
required registry keys by default. These will be used to find the install path among other things

## Usage
Once available, the filter itself is intended to be installed on all domain controllers (DCs) in your environment, as authentication is distributed among them. After being installed, a reboot will be required for
Windows LSA to register the DLL on boot. DFS-R will also be recommended for replicating the files necessary for the operation of the filter across the DCs.
