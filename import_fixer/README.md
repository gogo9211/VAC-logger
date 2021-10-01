# **Prerequisites**
* IDAPython version 3.x
* IDA version 7.x

# **How to use**
Go to `File` -> `Script File` and select the script on your computer.

Once the script is ran, you should see a new structure in IDA.

Find the import table in IDA, references to it should look like this

![Import Table](https://cdn.discordapp.com/attachments/855283499980423179/893572109517848576/unknown.png)

Once you've found it, select the table and press `Y`, or right-click and `Set item type`.
Then type in `vac_imports*` for the type of the import table, it should look like this.
![type definition](https://cdn.discordapp.com/attachments/855283499980423179/893572709433348106/unknown.png)

Now you're finished, it should look like this
![Fixed imports](https://cdn.discordapp.com/attachments/855283499980423179/893572881731174471/unknown.png)
