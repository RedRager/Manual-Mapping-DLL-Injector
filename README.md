# Manual Mapping DLL Injector

This is a manual mapping DLL injector written in c++. Its not much but it works. The injector can be compiled for both 64-bit and 32-bit architectures, depending on your requirements.
I build it to allow me to have a faster way to test my DLL while writing them rather then using cheat engine

This is my first c++ project and im sure theres several issues and better ways of doing things so if you have a suggestion please feel free to tell me

## How to use

1. Clone this repo
2. Choose which platform to build for (x86 or x64)
3. BBuild and launch the program
4. The program will prompt you for the path to your DLL and either the process ID or process name.
5. The program will run some check to make sure things are correct and then inject your DLL

## Todo
Ensure all errors are handled gracefully.
Do some cleanup and organisation.
Implement any possible improvements.
Consider adding a GUI at some point

Feel free to contribute, report issues, or suggest enhancements. Your input is highly appreciated!
