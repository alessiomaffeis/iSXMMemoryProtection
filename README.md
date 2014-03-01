iSXMMemoryProtection
============

iSXMMemoryProtection is a simple example module that statically analyzes the application’s executable binary with the purpose of determining if certain memory protection features have been enabled by the app’s developer. As a result, the module produces three metrics:

* mp_pie set to 1 whether PIE (Position Independent Executable) is active, 0 otherwise;
* mp_ssp set to 1 whether SSP (Stack Smashing Protection) is active), 0 otherwise;
* mp_arc set to 1 whether ARC (Automatic Reference Counting), 0 otherwise.
