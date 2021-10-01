# **Credits**
* [@gogo9211](https://github.com/gogo9211)
* 0x90 ([@AmJayden](https://github.com/AmJayden))

# **Log files**
Below is an explanation on each log file and what it contains, for ease of reading I will placehold the module name with `mod`.

Firstly, `mod.tmp` is a clone of the module that VAC uses, so you can reverse it.
`mod.txt` contains information on each import and the time it was resolved for that module.
`module_logs.txt` contains a log of each loaded module, it has the Time it was loaded, the handle, the function, and location of the module.

# **Insight on VAC imports**
VAC decrypts their encrypted import names at runtime, resolving them within their init function using GetProcAddress.

All modules (at least ones that I've checked) have the same import table.

Modules using excess imports resolve them in the caller functions with a different method shown below.
![Excess import resolving](https://cdn.discordapp.com/attachments/855283499980423179/893576200813944902/unknown.png)

Essentially it's  simple xor, for example, take `strcpy(v68, "]riho]rw~L")` and the key is 0x1B, so that would resolve to `FirstFileW`

On the import logs created by the logger, the first 2 imports shown are basically what they're using to decrypt other imports.
If you remove the first 2 imports, the rest of them are what's actually resolved, if in any case you need to update our import fixer script, take note of this.

Of course, VAC makes calls to their modules many times, in which imports are resolved per-call, some files may contain a lot of logs due to this.

Some imports may be directly called rather than a table index, so in future updates we may also include the location the import is written at after resolving it, but until then you can manually see what an import is.

# **How to use**
* Ensure your steam is **NOT** running as admin.
* Ensure that VMD is in a Folder and not directly under your drive directory, (eg: "C:\VMD\\" is okay but not "C:\\")

Inject the compiled dll into `steamservice.exe`, then load up a VAC game.
Once injected logs on VAC modules will begin to appear in the `(DLL_DIR)/logs` folder.

# **TODO**
* log the data passed to modules
* separate imports logged in the init from caller resolved imports
* log the address that resolved imports are written in
