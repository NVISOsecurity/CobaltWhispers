CC_64=x86_64-w64-mingw32-gcc
CFLAGS=-masm=intel
OUTPUT_PATH=$(CURDIR)
BUILD_PATH=$(OUTPUT_PATH/bin)

# Update with your installation path of InlineWhispers2
IW2=/opt/InlineWhispers2

generate_syscalls:
#	drivers
	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtClose,NtLoadDriver,NtUnloadDriver,NtCreateFile,NtWriteFile,NtFlushBuffersFile,NtDeleteFile,NtCreateKey,NtSetValueKey,NtOpenKeyEx,NtDeleteKey,NtOpenProcessToken,NtAdjustPrivilegesToken,NtQuerySystemInformation,NtDeviceIoControlFile,NtAllocateVirtualMemory,NtLockVirtualMemory,NtUnlockVirtualMemory,NtFreeVirtualMemory,NtSetSecurityObject,NtDuplicateObject,NtDelayExecution -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Drivers/DisableDSE

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtCreateFile,NtClose,NtDeviceIoControlFile -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Drivers/Intercept

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtOpenProcessToken,NtAdjustPrivilegesToken,NtClose,NtUnloadDriver,NtOpenKeyEx,NtDeleteKey,NtDeleteFile,NtDelayExecution -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Drivers/UnloadDriver

#	injection
	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtClose,NtOpenProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtFreeVirtualMemory,NtCreateThreadEx -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Injection/CreateRemoteThread

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtClose,NtOpenProcess,NtResumeThread,NtCreateSection,NtMapViewOfSection,NtGetContextThread,NtSetContextThread,NtUnmapViewOfSection,NtFreeVirtualMemory -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Injection/MapViewOfSection

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtClose,NtCreateTransaction,NtCreateFile,NtWriteFile,NtReadFile,NtOpenProcess,NtMapViewOfSection,NtRollbackTransaction,NtResumeThread,NtCreateSection,NtGetContextThread,NtSetContextThread -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Injection/PhantomDLLHollowing

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtClose,NtOpenProcess,NtWriteVirtualMemory,NtAllocateVirtualMemory,NtOpenThread,NtSuspendThread,NtQueueApcThread,NtResumeThread,NtProtectVirtualMemory,NtFreeVirtualMemory -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Injection/QueueUserAPC

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtClose,NtOpenProcess -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Injection/SpawnProcess

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtCreateTransaction,NtCreateFile,NtWriteFile,NtCreateSection,NtMapViewOfSection,NtGetContextThread,NtSetContextThread,NtWriteVirtualMemory,NtOpenProcess,NtResumeThread,NtClose -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Injection/TransactedHollowing

#	persistence
	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtSetValueKey,NtOpenKeyEx,NtDeleteValueKey,NtClose -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Persistence/PersistElevatedRegKey

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtSetValueKey,NtOpenKeyEx,NtDeleteValueKey,NtClose -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Persistence/PersistElevatedUserInitRegKey

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtSetValueKey,NtOpenKeyEx,NtDeleteValueKey,NtClose -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Persistence/PersistScheduledTaskCOMHijack

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtSetValueKey,NtOpenKeyEx,NtDeleteValueKey,NtClose -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Persistence/PersistUserInitMprRegKey

	cd $(IW2)/SysWhispers2 && python3 syswhispers.py -f NtOpenKeyEx,NtDeleteValueKey,NtClose -o $(IW2)/SysWhispers2/syscalls_all && cd .. && python3 InlineWhispers2.py
	mv $(IW2)/output/syscalls-asm.h $(IW2)/output/syscalls.c $(IW2)/output/syscalls.h $(OUTPUT_PATH)/Persistence/PersistUserRegKey

drivers:
	$(CC_64) -o $(BUILD_PATH)/DisableDSE.o -c Drivers/DisableDSE/DisableDSE.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/Intercept.o -c Drivers/Intercept/Intercept.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/UnloadDriver.o -c Drivers/UnloadDriver/UnloadDriver.c $(CFLAGS)

injection:
	$(CC_64) -o $(BUILD_PATH)/CreateRemoteThread.o -c Injection/CreateRemoteThread/CreateRemoteThread.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/MapViewOfSection.o -c Injection/MapViewOfSection/MapViewOfSection.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/PhantomDLLHollowing.o -c Injection/PhantomDLLHollowing/PhantomDLLHollowing.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/QueueUserAPC.o -c Injection/QueueUserAPC/QueueUserAPC.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/SpawnProcess.o -c Injection/SpawnProcess/SpawnProcess.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/TransactedHollowing.o -c Injection/TransactedHollowing/TransactedHollowing.c $(CFLAGS)

persistence:
	$(CC_64) -o $(BUILD_PATH)/PersistElevatedRegKey.o -c Persistence/PersistElevatedRegKey/PersistElevatedRegKey.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/PersistElevatedUserInitRegKey.o -c Persistence/PersistElevatedUserInitRegKey/PersistElevatedUserInitRegKey.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/PersistScheduledTaskCOMHijack.o -c Persistence/PersistScheduledTaskCOMHijack/PersistScheduledTaskCOMHijack.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/PersistUserInitMprRegKey.o -c Persistence/PersistUserInitMprRegKey/PersistUserInitMprRegKey.c $(CFLAGS)
	$(CC_64) -o $(BUILD_PATH)/PersistUserRegKey.o -c Persistence/PersistUserRegKey/PersistUserRegKey.c $(CFLAGS)

clean:
	rm -rf $(BUILD_PATH)