using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace GlobalHotkey
{
    class Program
    {
        public class PPSSPPSymbolParser
        {
            public class SymbolInfo
            {
                public uint Address { get; set; }
                public string SAddress { get; set; }
                public string Name { get; set; }
                public uint Size { get; set; }
                public string MakeIdaSymbol() => $"_ZN{Name.Length}{Name}Ev";
                public string MakeIdaScriptForAddName(bool symbolname = true)
                { // from my MkIdaFuncDefScript
                    string str = "";
                    //str += "del_items(" + SAddress + ", DELIT_SIMPLE, 0x466DE0TODOENDPTR - " + SAddress + ");"; // не обязательно
                    str += "add_func(0x" + SAddress + ", BADADDR);";
                    str += "set_name(0x" + SAddress + ", \"" + (symbolname ? MakeIdaSymbol() : Name) + "\", SN_AUTO);";
                    return str;
                }
            }

            public static List<SymbolInfo> ParseSymbols(string filePath)
            {
                var symbols = new List<SymbolInfo>();

                foreach (var line in File.ReadAllLines(filePath))
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                        continue;

                    string saddr = parts[0];
                    if (!uint.TryParse(saddr, NumberStyles.HexNumber, null, out uint address))
                        continue;

                    var namePart = parts[1];
                    var commaIndex = namePart.IndexOf(',');
                    string name = commaIndex >= 0 ? namePart.Substring(0, commaIndex) : namePart;

                    uint size = 0;
                    if (commaIndex >= 0 && commaIndex + 1 < namePart.Length)
                    {
                        var sizeStr = namePart.Substring(commaIndex + 1);
                        uint.TryParse(sizeStr, NumberStyles.HexNumber, null, out size);
                    }

                    symbols.Add(new SymbolInfo
                    {
                        Address = address,
                        SAddress = saddr,
                        Name = name,
                        Size = size
                    });
                }

                return symbols;
            }
            public static void PrintSymbols(List<SymbolInfo> symbols)
            {
                foreach (var symbol in symbols.OrderBy(s => s.Address))
                    Console.WriteLine($"0x{symbol.Address:X8} {symbol.Name}, 0x{symbol.Size:X4}");
            }
            public static List<SymbolInfo> AddBase(List<SymbolInfo> symbols, uint baseaddr, bool repl)
            {
                return symbols.Select(symbol =>
                {
                    uint newAddress = repl ? baseaddr : symbol.Address + baseaddr;
                    string newSAddress = newAddress.ToString("X8");

                    return new SymbolInfo
                    {
                        Address = newAddress,
                        SAddress = newSAddress,
                        Name = repl ? symbol.Name.Replace("_" + symbol.SAddress, "_" + newSAddress) : symbol.Name,
                        Size = symbol.Size
                    };
                }).ToList();
            }
            public static List<SymbolInfo> SCEFilter(List<SymbolInfo> symbols)
            {// 08E9C0F4 zz_sceKernelQueryModuleInfo,0008  // 08B0BA8C zz___sceSasSetVoice,0008
                string pat = "zzsce";
                return symbols.Where(s => s.Name.ToLower().Replace("_", "").StartsWith(pat.ToLower()) && s.Name.Contains("_")).ToList();
            }
            [STAThread] // to main
            public static void MkIdaScript2MoveSceNames(string path)
            {
                List<SymbolInfo> symbols = ParseSymbols(path);
                symbols = SCEFilter(symbols);
                string sbuff = "";
                foreach (SymbolInfo s in symbols)
                    sbuff += s.MakeIdaScriptForAddName() + "\r\n";
                Clipboard.SetText(sbuff);
                Console.WriteLine($"symbols: {symbols.Count}");
                foreach (SymbolInfo s in symbols)
                    Console.WriteLine(sbuff);
                //Console.WriteLine($"{s.MakeIdaScriptForAddName()}");

            }
        }

        [STAThread]
        static void Main()
        {
            PPSSPPSymbolParser.MkIdaScript2MoveSceNames("symbols_.txt");
        }
    }
}