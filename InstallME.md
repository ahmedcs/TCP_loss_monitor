# Makefile update
If the source file has been changed, you need to update the name of the object file to match the new source file containing the module init_module and exit_module macros and the definition functions. SEE Makefile for more information.

Notice, you can include other source and header files but under the condition that there are a single source file containing the neccessary init_module and exit_module macros and their function.

# Installation steps

change your current directory to to where the source and Makefile is located then issue:

```
git clone https://github.com/ahmedcs/TCP_loss_monitor.git
cd TCP_loss_monitor
make
```

Now the output files is as follows:
```
loss_probe.o \& loss_probe.ko
```
The file ending with .o is the object file while the one ending in .ko is the module file


# Run
To install the module into the kernel
```
sudo insmode loss_probe.ko
```
Now the module will probe fast-retransmit and retransmission timeout events and dump the socket variables of interest into a PROC file named "loss_probe". The module creates two files in /proc/net named loss_probe1 for send related events and loss_probe2 for receive related events. This design is better to performance to avoid any locking by these mutual exclusive events (Refer to functions lossprobe_sprint1 and lossprobe_sprint2 for more details). To dump the output of the PROC file to your file of interest, use the following command:

```
sudo cat /proc/net/lossprobe1 >> lossprobe1.out;
sudo cat /proc/net/lossprobe1 >> lossprobe2.out;
```

Note that the parameters of the module are:
1- port: the TCP port number of applications that needs to be tracked, 0 is the default which tracks all ports.
2- bufsize: the capture buffer size used by the module 4 KBytes is the default.

However to call the module with different parameters issue the following:
```
sudo insmod loss_probe.ko port=80 bufsize=8192;
```


# Stop

To stop the loss_probe module and free the resources issue the following command:

```
sudo rmmod -f loss_probe;
```
