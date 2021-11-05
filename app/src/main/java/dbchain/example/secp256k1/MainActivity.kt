package dbchain.example.secp256k1

import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.gcigb.dbchain.*
import com.gcigb.dbchain.util.coding.HexUtil
import com.gcigb.dbchain.util.toJsonString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.bouncycastle.util.encoders.Hex

class MainActivity : AppCompatActivity() {
    private val list = listOf(
        "tooth",
        "source",
        "tiny",
        "frost",
        "biology",
        "island",
        "tent",
        "alien",
        "sure",
        "easily",
        "fancy",
        "roast"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val dbChainKey = MnemonicClient.importMnemonic(list)
        DBChain.withDBChainKey(dbChainKey)
        val mnemonic = dbChainKey.mnemonic
        // 测试签名、加密、解密
        testSign(DBChain.dbChainKey)
        findViewById<View>(R.id.btn).setOnClickListener {
            createApplication()
        }
    }

    private fun createApplication() {
        GlobalScope.launch(Dispatchers.IO) {


            // query token
            queryToken()

            // 测试创建一个库
            val appCode = testCreateApplication()

//      // val appCode = "4D1AOCPZVD"
            DBChain.withAppCode(appCode)

//      // 测试创建表
            testCreateTable()

//      // 测试注册函数
            testAddFunction()

//      // 测试调用函数
            testCallFunction()

//      // 测试查询接口
            testQuery()
        }
    }

    companion object {
        private const val TAG = "dbchain_test"
    }

    private suspend fun queryToken(){
        val token = getToken(DBChain.dbChainKey.address)
        println("token: $token")
    }


    private suspend fun testQuery() {
        val tableName = "student"
        val queriedArray = QueriedArray(table = tableName)
        val querier = querier(queriedArray)
        println("查询结果：${querier.isSuccess}")
        println("查询内容：${querier.content}")
    }

    private suspend fun testCallFunction() {
        val functionName = "insertData"
        val agreementBody = mutableListOf<String>()
        val tableName = "student"
        val value = mapOf(
            "name" to "小明",
            "age" to "18",
            "sex" to "男"
        )
        agreementBody.add(tableName)
        agreementBody.add(value.toJsonString())
        val agreement = agreementBody.toJsonString()
        val callFunction = callFunction(functionName, agreement)
        println("callFunction： $callFunction")
    }

    private suspend fun testAddFunction() {
        val functionName = "insertData"
        val description = "往表中添加一条数据"
        val body = """
        function $functionName(insertTable, value)
	        VALUE = jsonStringToMap(value)
	        id , err = InsertRow(insertTable, VALUE)
	        if (err ~= "") then
	        	return err
	        end
	        return ""
        end
    """.trimIndent()
        val addFunction = addFunction(functionName, description, body)
        println("addFunction： $addFunction")
    }

    private suspend fun testCreateTable() {
        val createTable = createTable("student", listOf("name", "age", "sex"))
        println("createTable： $createTable")
    }

    private suspend fun testCreateApplication(): String {
        var appCode = "-1"
        // 先查询库列表
        val applicationListBefore = queryApplication()

        // 创建库列表
        val createApplication = createApplication("school", "学校管理系统", false, DBChain.dbChainKey.address)
        println("创建库结果：$createApplication")

        // 再查询库列表
        val applicationListAfter = queryApplication()

        val beforeSize = applicationListBefore?.size ?: 0
        // 如果创库之后查到的是空 || 和创建之前列表一样，说明没有查到
        if (applicationListAfter == null || applicationListAfter.isEmpty() || beforeSize == applicationListAfter.size) {
            println("没有查到 appCode")
            return appCode
        }

        if (applicationListAfter.size - beforeSize > 1) {
            println("新增的超过了一个，不确定是哪一个")
            return appCode
        }
        appCode = if (applicationListAfter.size == 1) {
            applicationListAfter[0]
        } else {
            kotlin.run {
                applicationListAfter.forEach {
                    if (applicationListBefore?.indexOf(it) ?: -1 == -1) {
                        return@run it
                    }
                }
                "-1"
            }
        }
        return appCode
    }

    private fun testSign(dbChainKey: DbChainKey) {
        Log.i(TAG, "address: ${dbChainKey.address}")
        println("私钥Hex：${dbChainKey.privateKey32}")
        println("公钥33Hex：${dbChainKey.publicKey33}")
        println("公钥64Hex：${dbChainKey.publicKey64}")

        val signData = "Hello world".toByteArray()
        val sign = DBChain.dbChainEncrypt.sign(dbChainKey.privateKeyBytes, signData)
        println("sign：${HexUtil.encodeHexString(sign)}")
        val verify = DBChain.dbChainEncrypt.verify(Hex.decode(dbChainKey.publicKey64), signData, sign)
        println("验证结果：$verify")
    }
}