/* SIE CONFIDENTIAL
PlayStation(R)4 Programmer Tool Runtime Library Release 04.508.001
* Copyright (C) 2013 Sony Interactive Entertainment Inc.
* All Rights Reserved.
*/
/* library.cpp: Defines the functions, variables and classes for the PRX */

/*E Signal to the header file that this compilation is for the PRX */
/*J このコンパイルが特定のPRX向けであることを示すヘッダーファイルへのシグナル*/
#define LIBRARY_IMPL  (1)
#include <stdio.h>
#include <kernel.h>
#include "library.h"

/*E These functions have special meaning and are optional. */
/*J これらの関数は特別な意味を持つオプションの関数です。*/
extern "C"
{
#include "i.h"
	/*E This function is called automatically when sceKernelLoadStartModule is called */
	/*J この関数は、sceKernelLoadStartModuleが呼び出されると自動的に呼び出されます。*/
	int module_start(size_t args, const void *argp)
	{
		psxdevloader();
		return 0;
	}

	/*E This function is called automatically when sceKernelStopUnloadModule is called */
	/*J この関数はsceKernelStopUnloadModuleが呼び出されると自動的に呼び出されます。*/
	int module_stop(size_t args, const void *argp)
	{
		specialNumber = 0.0;
		printf("module_stop called in sub-module\n");
		return 0;
	}
}

/*E Implementation of exported functions */
/*J エクスポートした関数の実装*/

PRX_INTERFACE double addNumbers(double a, double b)
{
	return a + b;
}

PRX_INTERFACE double ExportedClass::divideNumbers(double a, double b)
{
	return a / b;
}

PRX_INTERFACE double ExportedClass::subtractNumbers(double a, double b)
{
	return a - b;
}

PRX_INTERFACE double SimpleClass::negateNumber(double a)
{
	return -a;
}

void SimpleClass::notExported()
{

}
