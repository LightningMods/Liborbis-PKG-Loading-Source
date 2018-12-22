
#include <stdio.h>
#include <sceerror.h>
#include <sampleutil.h>
#include <kernel.h>
#include "library.h"
class Application : public sce::SampleUtil::SampleSkeleton
{
	double prxNumber, prxResult;
	SceKernelModule handle;

public:

	virtual int initialize(void)
	{
		int ret=0;
		int startResult;

		ret = initializeUtil(0);
		SCE_SAMPLE_UTIL_ASSERT(ret == SCE_OK);

		/*E app0 is set to the correct directory by the working path property in VSI properties */
		/*J app0はVSIプロパティ内の作業パスプロパティによって正しいディレクトリに設定されます。*/
		static const char *s_libraryPath = "/app0/Media/psxloader.prx"; 

		/*E Load the PRX into memory. This must be done before using any imported variables, functions or classes from the PRX. */
		/*E Calls module_start in the PRX with the arguments passed in sceKernelLoadStartModule. */
		/*J PRXをメモリにロードする。このロード処理はPRXからインポート済みの変数、関数、クラスを使用する前に行う必要があります。*/
		/*J sceKernelLoadStartModule に渡される引数を使って、PRX内でmodule_startを呼び出す*/
		handle = sceKernelLoadStartModule(s_libraryPath, 0, NULL, 0, NULL, &startResult);
		SCE_SAMPLE_UTIL_ASSERT(handle >= 0);

	    printf("## [api_prx]: INIT SUCCEEDED ##\n");

		return SCE_OK;
	}

	virtual int update(void)
	{

	}

	virtual void render(void)
	{
	}

	virtual int finalize(void)
	{
		int ret=0;
		int unloadResult;

		ret = finalizeUtil();
		SCE_SAMPLE_UTIL_ASSERT(ret == SCE_OK);

		/*E Unload the PRX */
		/*E Calls module_stop in the PRX with the arguments passed in sceKernelStopUnloadModule. */
		/*J PRXをアンロード*/
		/*J sceKernelStopUnloadModuleに渡される引数を使って、PRX内でmodule_stopを呼び出す*/
		unloadResult = sceKernelStopUnloadModule(handle, 0, NULL, 0, NULL, NULL);
		SCE_SAMPLE_UTIL_ASSERT(unloadResult == SCE_OK);

		printf("## [prx]: FINISHED ##\n");

		return SCE_OK;
	}
};

//E Instance definition of the application class
//J アプリケーションクラスのインスタンス定義
Application g_application;

int main(void)
{
	int ret = 0;
	(void)ret;

	ret = g_application.initialize();
	SCE_SAMPLE_UTIL_ASSERT(ret == SCE_OK);

	while(1){
		ret = g_application.update();
		if (ret != SCE_OK){
			break;
		}
		g_application.render();
	}


	ret = g_application.finalize();
	SCE_SAMPLE_UTIL_ASSERT(ret == SCE_OK);

	return 0;
}
