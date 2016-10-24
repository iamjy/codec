
vpu-objs := mnhevc.o

obj-$(CONFIG_MV_VPU) +=src/mnhevc.o

ccflags-$(CONFIG_MV_VPU_DEBUG) := -DDEBUG=1
ccflags-y += -I$(srctree)/drivers/staging/android/ion
ccflags-y += -I$(srctree)/drivers/staging/android/ion/mv
ccflags-y += -I$(srctree)/drivers/media/platform/mv/codec/include
