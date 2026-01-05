const TARGET_DLL = "QQMusicCommon.dll";

// 解析函数地址
var EncAndDesMediaFileConstructorAddr = Module.findExportByName(
  TARGET_DLL, "??0EncAndDesMediaFile@@QAE@XZ"
);
var EncAndDesMediaFileDestructorAddr = Module.findExportByName(
  TARGET_DLL, "??1EncAndDesMediaFile@@QAE@XZ"
);
var EncAndDesMediaFileOpenAddr = Module.findExportByName(
  TARGET_DLL, "?Open@EncAndDesMediaFile@@QAE_NPB_W_N1@Z"
);
var EncAndDesMediaFileGetSizeAddr = Module.findExportByName(
  TARGET_DLL, "?GetSize@EncAndDesMediaFile@@QAEKXZ"
);
var EncAndDesMediaFileReadAddr = Module.findExportByName(
  TARGET_DLL, "?Read@EncAndDesMediaFile@@QAEKPAEK_J@Z"
);

// 构造函数
var EncAndDesMediaFileConstructor = new NativeFunction(
  EncAndDesMediaFileConstructorAddr, "pointer", ["pointer"], "thiscall"
);
var EncAndDesMediaFileDestructor = new NativeFunction(
  EncAndDesMediaFileDestructorAddr, "void", ["pointer"], "thiscall"
);
var EncAndDesMediaFileOpen = new NativeFunction(
  EncAndDesMediaFileOpenAddr, "bool", ["pointer", "pointer", "bool", "bool"], "thiscall"
);
var EncAndDesMediaFileGetSize = new NativeFunction(
  EncAndDesMediaFileGetSizeAddr, "uint32", ["pointer"], "thiscall"
);
var EncAndDesMediaFileRead = new NativeFunction(
  EncAndDesMediaFileReadAddr, "uint", ["pointer", "pointer", "uint32", "uint64"], "thiscall"
);

// Windows API: CreateDirectoryW
var CreateDirectoryW = new NativeFunction(
  Module.getExportByName("kernel32.dll", "CreateDirectoryW"),
  "bool", ["pointer", "pointer"]
);

// 递归创建路径
function ensureDirRecursively(pathStr) {
  const parts = pathStr.split(/[\\/]/);
  let current = parts[0] === "" ? parts[0] + "\\" : parts[0];
  for (let i = 1; i < parts.length; i++) {
    current += "\\" + parts[i];
    const wide = Memory.allocUtf16String(current);
    CreateDirectoryW(wide, ptr(0));
  }
}

rpc.exports = {
  decrypt: function (srcFileName, tmpFileName) {
    // 构造对象
    var EncAndDesMediaFileObject = Memory.alloc(0x28);
    EncAndDesMediaFileConstructor(EncAndDesMediaFileObject);

    var fileNameUtf16 = Memory.allocUtf16String(srcFileName);
    var opened = EncAndDesMediaFileOpen(EncAndDesMediaFileObject, fileNameUtf16, 1, 0);
    if (!opened) {
      EncAndDesMediaFileDestructor(EncAndDesMediaFileObject);
      throw new Error("打开失败: " + srcFileName);
    }

    // 读取数据
    var fileSize = EncAndDesMediaFileGetSize(EncAndDesMediaFileObject);
    var buffer = Memory.alloc(fileSize);
    EncAndDesMediaFileRead(EncAndDesMediaFileObject, buffer, fileSize, 0);

    var data = buffer.readByteArray(fileSize);
    EncAndDesMediaFileDestructor(EncAndDesMediaFileObject);

    // 创建输出目录（递归）
    var lastSlash = tmpFileName.lastIndexOf("\\");
    if (lastSlash !== -1) {
      var dirPath = tmpFileName.substring(0, lastSlash);
      ensureDirRecursively(dirPath);
    }

    // 写入文件
    var tmpFile = new File(tmpFileName, "wb");
    tmpFile.write(data);
    tmpFile.flush();
    tmpFile.close();
  }
};
