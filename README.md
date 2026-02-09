<h1>ShellcodeRunPE – Encrypted Shellcode PE Loader</h1>

<p><strong>ShellcodeRunPE</strong> is a compact x64 assembly-based loader that decrypts and executes an embedded PE file entirely in memory using a custom XOR encryption scheme.</p>

<p>The loader implements a minimal RunPE-style execution flow without relying on the Windows loader.</p>

<hr>

<h2>Overview</h2>

<p>This project demonstrates how to:</p>

<ul>
  <li>Embed an encrypted executable payload directly into an assembly binary</li>
  <li>Decrypt the payload at runtime using a custom XOR key</li>
  <li>Manually load a PE file in memory</li>
  <li>Resolve imports dynamically</li>
  <li>Apply base relocations</li>
  <li>Masquerade process command-line arguments</li>
  <li>Execute the payload without writing it to disk</li>
</ul>

<p>All required Windows APIs are resolved dynamically at runtime:</p>

<ul>
  <li>LoadLibraryA</li>
  <li>GetProcAddress</li>
  <li>VirtualAlloc</li>
  <li>VirtualProtect</li>
  <li>WideCharToMultiByte</li>
</ul>

<p>The loader does not depend on any external libraries at compile time.</p>

<hr>

<h2>Features</h2>

<ul>
  <li>Custom XOR encryption of embedded payload</li>
  <li>Manual PE loading (RunPE technique)</li>
  <li>Import Address Table reconstruction</li>
  <li>Base relocation support</li>
  <li>Command-line argument masquerading</li>
  <li>Fully in-memory execution</li>
  <li>Written entirely in FASM x64 assembly</li>
</ul>

<hr>

<h2>How It Works</h2>

<ol>
  <li>The payload (any Windows PE executable) is embedded into the loader using the <code>xor_incbin</code> macro.</li>
  <li>At compile time, the macro encrypts the file using a user-defined XOR key.</li>
  <li>When executed, the loader:</li>
</ol>

<ul>
  <li>Resolves required Windows API functions</li>
  <li>Allocates memory for the encrypted payload</li>
  <li>Decrypts the payload in memory</li>
  <li>Parses PE headers</li>
  <li>Maps sections manually</li>
  <li>Fixes imports and relocations</li>
  <li>Transfers execution to the original entry point</li>
</ul>

<hr>

<h2>Building</h2>

<h3>Requirements</h3>

<p>Flat Assembler (FASM) is required:</p>

<p><a href="https://flatassembler.net/">https://flatassembler.net/</a></p>

<h3>Compile</h3>

<pre>
fasm ShellcodeRunPE.asm ShellcodeRunPE.bin
</pre>

<p>The output will be a raw executable binary containing your encrypted payload.</p>

<hr>

<h2>Usage</h2>

<h3>1. Choose a Payload</h3>

<p>Select any Windows PE executable you want to embed.</p>

<p>Example:</p>

<pre>
C:\example\path\file.exe
</pre>

<h3>2. Configure Encryption Key</h3>

<p>Modify the key in the source code:</p>

<pre>
key db 0x0B,0x99,0xDE,0x10,0xF2,0x5D,0xA5,0xA1,0x73,0x3E,0xA0,0x6D,0x51,0xC1,0x90,0xEE
key_size = 16
</pre>

<p>You may change both the values and key length.</p>

<h3>3. Set Payload Path</h3>

<p>At the bottom of the source file:</p>

<pre>
payload:
    xor_incbin 'C:\example\path\file.exe'
</pre>

<p>Replace the path with your actual payload.</p>

<h3>4. Compile</h3>

<p>Run FASM to generate the final loader containing the encrypted executable.</p>

<hr>

<h2>Customization</h2>

<p>You can modify:</p>

<ul>
  <li>Encryption key and size</li>
  <li>Embedded payload</li>
  <li>Default command line value</li>
</ul>

<hr>

<h2>Technical Components</h2>

<p>The loader implements the following core routines:</p>

<ul>
  <li><code>decrypt_loop</code> – XOR decryption routine</li>
  <li><code>get_kernel32</code> – Locate kernel32 base address</li>
  <li><code>get_proc_addr</code> – Resolve API functions</li>
  <li><code>pe_loader</code> – Manual PE mapping logic</li>
  <li><code>fix_iat</code> – Import resolution</li>
  <li><code>apply_reloc</code> – Base relocation fixups</li>
  <li><code>masquerade_cmdline</code> – Argument spoofing</li>
</ul>

<p>Hooked functions include:</p>

<ul>
  <li>GetCommandLineA / GetCommandLineW</li>
  <li>__getmainargs</li>
  <li>__wgetmainargs</li>
</ul>

<hr>

<h2>Limitations</h2>

<ul>
  <li>64-bit Windows PE files only</li>
  <li>No ASLR bypass (relies on relocations)</li>
  <li>No exception handling support</li>
  <li>No TLS callback support</li>
  <li>Designed primarily for research and learning</li>
</ul>

<hr>

<h2>Disclaimer</h2>

<p>
This project is intended strictly for <strong>educational, research, and defensive security purposes</strong>.
</p>

<p>
The author and contributors are not responsible for any misuse of this code.  
Use only on systems you own or have explicit permission to test.
</p>

<hr>

<h2>License</h2>

<p>Apache 2.0</p>

<hr>

<p>Feel free to fork, experiment, and improve the project!</p>
