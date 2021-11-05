package dbchain.example.secp256k1

import android.app.Application
import android.util.Log
import com.gcigb.dbchain.DBChain
import com.gcigb.dbchain.ILog
import com.gcigb.dbchain.util.toJsonString
import dbchain.client.java.secp256k1.Secp256k1Encrypt

class BaseApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        val appCode = "Your AppCode"
        val baseUrl = "http://192.168.0.19/relay/"
        val chainId = "testnet"
        val debug = true
        DBChain.init(
            appCode = appCode,
            baseUrl = baseUrl,
            chainId = chainId,
            isDebug = debug,
            dbChainEncrypt = Secp256k1Encrypt(),
            iLog = LogImpl(),
            defaultGasNumber = 200000
        )
    }
}

class LogImpl : ILog {
    override fun logHttp(msg: String) {
        Log.i("http", msg)
    }

    override fun logV(tag: String, msg: String) {
        Log.i(tag, msg)
    }

    override fun logD(tag: String, msg: String) {
        Log.i(tag, msg)
    }

    override fun logI(msg: String) {
        Log.i("dss_test", msg)
    }

    override fun logI(any: Any) {
        Log.i("dss_test", any.toJsonString())
    }

    override fun logI(tag: String, msg: String) {
        Log.i(tag, msg)
    }

    override fun logW(tag: String, msg: String) {
        Log.i(tag, msg)
    }

    override fun logE(msg: String) {
        Log.i("dss_test", msg)
    }

    override fun logE(tag: String, msg: String) {
        Log.i(tag, msg)
    }

}