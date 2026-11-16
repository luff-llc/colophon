package works.luff.colophon.testapp

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.view.Surface
import android.view.TextureView
import android.widget.LinearLayout
import android.widget.TextView
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.BarcodeFormat
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Scans a Colophon test invite or request with the camera (camera2 preview, ZXing on the luminance plane) and returns
 * its text as `RESULT`. On an emulator the camera is the emulator's virtual scene: paste instead.
 */
class ScanActivity : Activity() {
    companion object { const val RESULT = "payload" }

    private lateinit var preview: TextureView
    private lateinit var status: TextView
    private var thread: HandlerThread? = null
    private var handler: Handler? = null
    private var camera: CameraDevice? = null
    private var reader: ImageReader? = null
    @Volatile private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        preview = TextureView(this)
        status = TextView(this).apply { text = "Point the camera at the other device's code."; setPadding(24, 24, 24, 24) }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(status)
            addView(preview, LinearLayout.LayoutParams(-1, 0, 1f))
        })
    }

    override fun onResume() {
        super.onResume()
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), 1); return
        }
        start()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, results: IntArray) {
        if (results.firstOrNull() == PackageManager.PERMISSION_GRANTED) start() else status.text = "No camera permission: paste the payload instead."
    }

    override fun onPause() { stop(); super.onPause() }

    private fun start() {
        if (camera != null) return
        val t = HandlerThread("scan").also { it.start() }
        thread = t; handler = Handler(t.looper)
        if (preview.isAvailable) open() else preview.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(s: SurfaceTexture, w: Int, h: Int) = open()
            override fun onSurfaceTextureSizeChanged(s: SurfaceTexture, w: Int, h: Int) {}
            override fun onSurfaceTextureDestroyed(s: SurfaceTexture) = true
            override fun onSurfaceTextureUpdated(s: SurfaceTexture) {}
        }
    }

    private fun open() {
        val manager = getSystemService(CAMERA_SERVICE) as CameraManager
        val id = manager.cameraIdList.firstOrNull { manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK }
            ?: manager.cameraIdList.firstOrNull() ?: run { status.text = "No camera here: paste the payload instead."; return }
        val reader = ImageReader.newInstance(1280, 720, ImageFormat.YUV_420_888, 2).also { this.reader = it }
        reader.setOnImageAvailableListener({ r ->
            val image = r.acquireLatestImage() ?: return@setOnImageAvailableListener
            try {
                if (done) return@setOnImageAvailableListener
                val plane = image.planes[0]
                val buffer = plane.buffer
                val data = ByteArray(buffer.remaining()).also { buffer.get(it) }
                val source = PlanarYUVLuminanceSource(data, plane.rowStride, image.height, 0, 0, image.width, image.height, false)
                val text = try {
                    QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))).text
                } catch (_: Exception) { null }
                if (text != null && PairingPayload.kind(text) != null) {
                    done = true
                    runOnUiThread { setResult(RESULT_OK, Intent().putExtra(RESULT, text)); finish() }
                }
            } finally { image.close() }
        }, handler)
        try {
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    val texture = preview.surfaceTexture ?: return
                    texture.setDefaultBufferSize(1280, 720)
                    val surfaces = listOf(Surface(texture), reader.surface)
                    val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply { surfaces.forEach { addTarget(it) } }.build()
                    device.createCaptureSession(SessionConfiguration(SessionConfiguration.SESSION_REGULAR, surfaces.map { OutputConfiguration(it) },
                        { it.run() }, object : CameraCaptureSession.StateCallback() {
                            override fun onConfigured(session: CameraCaptureSession) { session.setRepeatingRequest(request, null, handler) }
                            override fun onConfigureFailed(session: CameraCaptureSession) { runOnUiThread { status.text = "The camera could not start." } }
                        }))
                }
                override fun onDisconnected(device: CameraDevice) { device.close(); camera = null }
                override fun onError(device: CameraDevice, error: Int) { device.close(); camera = null; runOnUiThread { status.text = "Camera error $error." } }
            }, handler)
        } catch (e: SecurityException) { status.text = "No camera permission." }
    }

    private fun stop() {
        camera?.close(); camera = null
        reader?.close(); reader = null
        thread?.quitSafely(); thread = null; handler = null
    }
}
