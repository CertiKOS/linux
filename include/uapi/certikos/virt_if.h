#ifndef _VIRT_IF_H_
#define _VIRT_IF_H_

#if defined(_KERN_)
#include <lib/types.h>

#if (_virt_ == _hava_intel_vmx_)
#include <arch/i386/virt/virt_if.h>
#elif (_virt_ == _hava_arm_ve_)
#include <arch/arm/virt/virt_if.h>
#endif

#elif defined(_USER_)

#if (_virt_ == _hava_intel_vmx_)
#include <i386/virt_if.h>
#elif (_virt_ == _hava_arm_ve_)
#include <arm/virt_if.h>
#endif

#endif /* _KERN_ vs. _USER_ */

enum virt_control_t
{
	VIRT_INIT = 0,
	VIRT_RUN,
	VIRT_STOP,

	MAX_VIRT_CONTROLS
};

#endif /* !_VIRT_IF_H_ */
