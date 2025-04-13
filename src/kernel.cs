using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

using Microsoft.Win32;

namespace CTermSrvPatcher {
	public static class CKernel {
		public const string ServiceName = "TermService";
		public static byte[] DefaultSource = new byte[] { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0x97, 0x49, 0x01, 0x00 };
		public static byte[] DefaultTarget = new byte[] { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };
		static string filePath = null, configPath = null;
		static bool autoFlag = false, outputToStdout = false, allowJmpPatch = true;
		static byte[] source = null, target = null;
		static string EXEName { get => Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().Location); }

		/// <summary>The main entry point for the application.</summary>
		[STAThread()] static int Main(string[] args) {
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			for (int i = 0; i < args.Length; i++) {
				var arg = args[i];
				var nextArg = i + 1 < args.Length ? args[i + 1] : null;
				switch (arg) {
					case "-?": case "--help": printUsage(); return 0;
					case "-a": case "--auto": autoFlag = true; break;
					case "-r": case "--restore": return restoreOriginalBackup(filePath);
					case "-j": case "--allow-jmp-patch": allowJmpPatch = true; break;
					case "-j-": case "--no-jmp-patch": allowJmpPatch = false; break;
					case "-s": case "--source": source = parseHex(nextArg); i++; break;
					case "-t": case "--target": target = parseHex(nextArg); i++; break;
					case "-f": case "--file": filePath = nextArg; i++; break;
					case "-c": case "--config": configPath = nextArg; i++; break;
					case "-v": case "--version": printAppVersion(); return 0;
					case "-tv": case "--tsver": case "--ts-version": return printTermsrvVersion();
				}
			}
			if (filePath == null) { filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "termsrv.dll"); }
			if (filePath == "-") { outputToStdout = true; filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "termsrv.dll"); }
			initRDPSettings();
			if (source == null || target == null) {
				var iniPath = resolveIniPath(configPath);
				if (File.Exists(iniPath)) {
					var config = File.ReadAllLines(iniPath);
					if (source == null) { source = parseHex(readValue(config, "source")); }
					if (target == null) { target = parseHex(readValue(config, "target")); }
				}
			}
			var original = readFileWithRetry(filePath);
			if (!autoFlag && (source == null || target == null)) {
				source = source ?? DefaultSource;
				target = target ?? DefaultTarget;
			}
			int sourceOffset = -1, targetOffset = -1;
			if (source == null || target == null) {
				var result = analyzeAndSuggestPatch(original);
				if (result == null && allowJmpPatch) { result = analyzeAndSuggestJmpPatch(original); }
				if (result != null) {
					source = result.Item1; target = result.Item2;
					sourceOffset = findPattern(original, source); targetOffset = findPattern(original, target);
					if (sourceOffset == -1 && targetOffset != -1) { Console.WriteLine("[info] Patch already applied (confirmed by content)"); return 0; }
					Console.WriteLine($"[info] Patch auto-selected at [0x${result.Item3:X}]");
				}
				else { Console.Error.WriteLine("[error] No default or matching patch found. File may be already patched"); return -2; }
			}
			if (sourceOffset < 0) { sourceOffset = findPattern(original, source); }
			if (targetOffset < 0) { targetOffset = findPattern(original, target); }
			// Eğer source ve target aynı yerdeyse → patch zaten uygulanmış
			if (sourceOffset == -1 && targetOffset != -1) { Console.WriteLine("[info] Patch already applied."); return 0; }
			// Eğer source ve target farklı offset'teyse, başka bir 'je' ile karışıyor olabilir
			if (sourceOffset != -1 && targetOffset == sourceOffset) { Console.WriteLine("[info] Target already present at source offset. Skipping."); return 0; }
			/* &modified[0] + sourceOffset */
			var modified = (byte[])original.Clone(); for (int i = 0; i < target.Length; i++) { modified[sourceOffset + i] = target[i]; }
			if (outputToStdout) {
				Console.WriteLine(BitConverter.ToString(modified).Replace("-", " "));
			}
			else {
				if (original.SequenceEqual(modified)) {
					Console.Error.WriteLine("[error] File seems to be already patched");
					return -6;
				}
				ServiceController service = null;
				foreach (var _service in ServiceController.GetServices()) {
					if (_service.ServiceName == ServiceName) { service = _service; break; }
					_service.Close();
				}
				var wasRunning = !(service == null || service.Status == ServiceControllerStatus.Stopped || service.Status == ServiceControllerStatus.StopPending);
				if (wasRunning) { service.Stop(); service.WaitForStatus(ServiceControllerStatus.Stopped); service.Refresh(); }
				try { writeFileWithRetry(filePath, modified); }
				finally {
					if (wasRunning) { service.Start(); }
					service?.Close();
				}
				Console.WriteLine("[done] Patched file written to: " + filePath);
			}
			return 0;
		}
		static void initRDPSettings(int? maxConnections = null, bool limitOneUserPerSession = false) {
			maxConnections = maxConnections ?? 999999;
			try {
				using (var regKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", true)) {
					regKey.SetValue("MaxInstanceCount", maxConnections.Value, RegistryValueKind.DWord);
					Console.WriteLine($"[done] MaxInstanceCount set to {maxConnections.Value}");
					regKey.SetValue("fSingleSessionPerUser", limitOneUserPerSession ? 1 : 0, RegistryValueKind.DWord);
					Console.WriteLine($"[done] fSingleSessionPerUser set to {(limitOneUserPerSession ? 1 : 0)}");
				}
			}
			catch (UnauthorizedAccessException) { Console.Error.WriteLine("[error] Access denied. Please run as Administrator."); }
			catch (Exception ex) { Console.Error.WriteLine("[error] " + ex.Message); }
		}
		static void printAppVersion() {
			var asm = Assembly.GetExecutingAssembly();
			var name = asm.GetCustomAttribute<AssemblyProductAttribute>()?.Product ?? "PatchTool";
			var version = asm.GetName().Version?.ToString();
			Console.WriteLine(name + "\t" + version);
		}
		static int printTermsrvVersion() {
			string file = filePath;
			if (!File.Exists(file)) { Console.WriteLine("File	Not Found"); return -5; }
			var info = FileVersionInfo.GetVersionInfo(file);
			Console.WriteLine("FileVersion	" + info.FileVersion);
			Console.WriteLine("ProductVersion	" + info.ProductVersion);
			return 0;
		}
		static int restoreOriginalBackup(string path) {
			try { return restoreOriginalBackup_internal(path); }
			catch (Exception ex) when (ex is IOException || ex is SecurityException || ex is UnauthorizedAccessException) {
				takeOwnership(path);
				return restoreOriginalBackup_internal(path);
			}
		}
		static int restoreOriginalBackup_internal(string path) {
			var bckPath = path + ".bak";
			if (!File.Exists(bckPath)) { Console.Error.WriteLine("[error] Backup file not found: " + bckPath); return -10; }
			try {
				if (File.Exists(path)) { File.Delete(path); } File.Move(bckPath, path);
				Console.WriteLine("[done] Restored original file from backup.");
				return 0;
			}
			catch (Exception ex) { Console.Error.WriteLine("[error] Failed to restore: " + ex.Message); return -11; }
		}
		static string resolveIniPath(string configPath) {
			if (!string.IsNullOrEmpty(configPath)) return configPath;
			var working = Path.Combine(Directory.GetCurrentDirectory(), EXEName + ".ini");
			if (File.Exists(working)) return working;
			var exeDir = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), EXEName + ".ini");
			return exeDir;
		}
		static string readValue(string[] lines, string key) {
			foreach (var line in lines) {
				if (line.Trim().StartsWith(key + "=", StringComparison.OrdinalIgnoreCase)) {
					return line.Split('=')[1].Trim();
				}
			}
			return null;
		}
		static byte[] parseHex(string hex) {
			if (string.IsNullOrWhiteSpace(hex)) return null;
			return hex.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries)
					  .Select(s => Convert.ToByte(s, 16)).ToArray();
		}
		static int findPattern(byte[] data, byte[] pattern) {
			for (int i = 0; i <= data.Length - pattern.Length; i++) {
				var  match = true;
				for (int j = 0; j < pattern.Length; j++) {
					if (pattern[j] != data[i + j]) { match = false; break; }
				}
				if (match) { return i; }
			}
			return -1;
		}
		static Tuple<byte[], byte[], int> analyzeAndSuggestPatch(byte[] data) {
			byte[] prefix = { 0x39, 0x81 };
			for (int i = 0; i < data.Length - 12; i++) {
				if (!(data[i] == prefix[0] && data[i + 1] == prefix[1] && data[i + 6] == 0x0F && data[i + 7] == 0x84)) { continue; }
				byte[] src = data.Skip(i).Take(12).ToArray();
				byte offset0 = src[2], offset1 = src[3], offset2 = src[4];
				int fullOffset = offset0 + (offset1 << 8) + (offset2 << 16);
				int patchedOffset = fullOffset - 4;
				byte[] patchTarget = {
					0xB8, 0x00, 0x01, 0x00, 0x00,
					0x89, 0x81,
					(byte)(patchedOffset & 0xFF),
					(byte)((patchedOffset >> 8) & 0xFF),
					(byte)((patchedOffset >> 16) & 0xFF),
					0x00,
					0x90
				};
				return Tuple.Create(src, patchTarget, i);
			}
			return null;
		}
		static Tuple<byte[], byte[], int> analyzeAndSuggestJmpPatch(byte[] data) {
			for (int i = 0; i < data.Length - 6; i++) {
				if (data[i] != 0x0F || data[i + 1] != 0x84) { continue; }
				byte[] src = data.Skip(i).Take(6).ToArray();
				byte[] offset = src.Skip(2).Take(4).ToArray();
				// Patch’lenmiş hali oluştur
				byte[] dst = new byte[6]; dst[0] = 0xE9; Array.Copy(offset, 0, dst, 1, 4); dst[5] = 0x90;
				// Eğer zaten patch'li ise atla
				if (data.Skip(i).Take(6).SequenceEqual(dst)) { continue; }
				// Bu JE'nin hedef uzaklığı çok küçükse, sistemsel değil demektir
				int jumpOffset = BitConverter.ToInt32(offset, 0);
				if (jumpOffset < 0x80 || jumpOffset > 0x100000) { continue; }
				// sadece anlamlı JE'yi öner
				return Tuple.Create(src, dst, i);
			}
			return null;
		}
		static byte[] readFileWithRetry(string path) {
			try { return File.ReadAllBytes(path); }
			catch (Exception ex) when (ex is IOException || ex is SecurityException || ex is UnauthorizedAccessException) {
				takeOwnership(path);
				return File.ReadAllBytes(path);
			}
		}
		static void writeFileWithRetry(string path, byte[] data) {
			try { writeFileWithRetry_internal(path, data); }
			catch (Exception ex) when (ex is IOException || ex is SecurityException || ex is UnauthorizedAccessException) {
				takeOwnership(path);
				writeFileWithRetry_internal(path, data);
			}
		}
		static void writeFileWithRetry_internal(string path, byte[] data) {
			if (File.Exists(path)) {
				var bckPath = path + ".bak";
				if (File.Exists(bckPath)) { File.Delete(bckPath); }
				File.Move(path, bckPath);
			}
			File.WriteAllBytes(path, data);
		}
		static void takeOwnership(string path) {
			Console.WriteLine("[warn] Retrying with ownership claim...");
			Process.Start(new ProcessStartInfo {
				FileName = "cmd.exe",
				Arguments = $"/c takeown /f \"{path}\" && icacls \"{path}\" /grant Administrators:F",
				CreateNoWindow = true, UseShellExecute = false,
				WindowStyle = ProcessWindowStyle.Hidden
			}).WaitForExit();
		}
		static void printUsage() {
			Console.WriteLine("Usage:");
			Console.WriteLine("  -a  | --auto                          Analyze & Auto Patch");
			Console.WriteLine("  -r  | --restore                       Restore Original 'termsrv.dll' File");
			Console.WriteLine("  -s  | --source        <hex bytes>     e.g. 39 81 3C 06 ...");
			Console.WriteLine("  -t  | --target        <hex bytes>     e.g. B8 00 01 00 ...");
			Console.WriteLine("  -f  | --file          <path|->        defaults to system32/termsrv.dll, '-' = stdout");
			Console.WriteLine("  -c  | --config        <ini path>      default: exeName.ini in working dir or exe dir");
			Console.WriteLine("  -v  | --version                       show app version");
			Console.WriteLine("  -tv | --tsver|--ts-version            show termsrv.dll version");
			Console.WriteLine("  -j  | --allow-jmp-patch               Allow JMP based patch");
			Console.WriteLine("  -j- | --no-jmp- patch                 DENY JMP based patch");
			Console.WriteLine("  -?  | --help                          show this message");
			Console.WriteLine();
			Console.WriteLine("  Made with ❤️ by a!cbr00t-CGPR ✊");
		}
	}
	/*
	  Patch logic by a!cbr00t-CGPR
	  This code is designed to assist in safely and reversibly patching termsrv.dll for multi-session RDP.
	  Built on .NET Framework 4.6.2 as a standalone utility for educational and administrative use.
	*/
		}
