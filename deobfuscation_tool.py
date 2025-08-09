def deobfuscate_password(obfuscated_text):
    """
    難読化されたパスワードを元に戻す関数
    
    Args:
        obfuscated_text (str): 難読化されたテキスト
    
    Returns:
        str: 復号化されたオリジナルのパスワード
    """
    # 2,3文字目から元のパスワード長を取得
    length_hex = obfuscated_text[1:3]
    original_length = int(length_hex, 16)
    
    # 4文字目から7文字間隔で元の文字を抽出
    decrypted = ""
    start_pos = 3  # 4文字目は位置3（0から数えて）
    
    for i in range(original_length):
        pos = start_pos + i * 7
        decrypted += obfuscated_text[pos]
    
    return decrypted

# 分析用の関数を追加
def analyze_coordinates(decoded_text):
    """
    復号化されたテキストからXZ座標を抽出・解析
    """
    print(f"復号化されたテキスト: {decoded_text}")
    print(f"文字数: {len(decoded_text)}")
    
    # X座標とZ座標を探す
    x_pos = decoded_text.find('X')
    z_pos = decoded_text.find('Z')
    
    if x_pos == -1 or z_pos == -1:
        print("XまたはZ座標が見つかりません")
        return
    
    print(f"Xの位置: {x_pos}, Zの位置: {z_pos}")
    
    # X座標後の16進数を抽出
    x_hex = ""
    for i in range(x_pos + 1, len(decoded_text)):
        if decoded_text[i] in "0123456789ABCDEFabcdef":
            x_hex += decoded_text[i]
        else:
            break
    
    # Z座標後の16進数を抽出
    z_hex = ""
    for i in range(z_pos + 1, len(decoded_text)):
        if decoded_text[i] in "0123456789ABCDEFabcdef":
            z_hex += decoded_text[i]
        else:
            break
    
    print(f"X後の16進数: {x_hex}")
    print(f"Z後の16進数: {z_hex}")
    
    # 12バイト符号付き整数として解釈を試行
    def hex_to_signed_12byte(hex_str):
        if len(hex_str) > 24:  # 12バイト = 24文字
            hex_str = hex_str[:24]
        elif len(hex_str) < 24:
            hex_str = hex_str.ljust(24, '0')  # 右をゼロパディング
        
        # 16進数を整数に変換
        value = int(hex_str, 16)
        
        # 12バイト符号付きの範囲チェック（-2^95 to 2^95-1）
        max_val = 2**95 - 1
        if value > max_val:
            value -= 2**96
        
        return value
    
    if x_hex:
        x_value = hex_to_signed_12byte(x_hex)
        print(f"X座標値: {x_value}")
    
    if z_hex:
        z_value = hex_to_signed_12byte(z_hex)
        print(f"Z座標値: {z_value}")

def analyze_hex_patterns(decoded_text):
    """
    復号化テキスト内の16進数パターンを全て分析
    """
    print("\n=== 16進数パターン分析 ===")
    
    # 12文字の16進数パターンを探す（FFFFFFFFFCE0のような）
    import re
    hex_patterns = re.findall(r'[0-9A-Fa-f]{12}', decoded_text)
    
    print("見つかった12桁16進数パターン:")
    for i, pattern in enumerate(hex_patterns):
        # 符号付き12バイトとして解釈
        value = int(pattern, 16)
        if value >= 2**47:  # 12バイトの半分で符号判定
            signed_value = value - 2**48
        else:
            signed_value = value
        
        print(f"  {i+1}. {pattern} -> {signed_value}")

# 暗号
obfuscated_text = "N1AXpHiArjFE(nGCZFdUTrZiFexUbs$F%RFt@eFv(u(MBFZVJBSYFdVNGT)FimLpjjFswJD@oCC(@eMgEipnGZe0LarJbeZLsWCjPFFUNz)WFonvLkkFE)Wmg@FnzcyuPFkqcYlrFqg&GizFLc(IdFFQgWSVZFVXuPk$CIbI)N*EUXI&FT0eXTPKn"

result = deobfuscate_password(obfuscated_text)
print("復号化結果:", result)
print()

def try_different_interpretations():
    """
    FFFFFFFFFCE0を-800と-1900として解釈する方法を探る
    """
    print("\n=== 異なる解釈方法の検証 ===")
    
    hex_val = "FFFFFFFFFCE0"
    target_values = [-800, -1900]
    
    print(f"対象16進数: {hex_val}")
    print(f"目標値: {target_values}")
    
    # 様々な解釈方法を試す
    print("\n異なるバイト長での解釈:")
    
    # 4バイト符号付き
    val_4byte = int(hex_val[-8:], 16)  # 下位4バイト
    if val_4byte >= 2**31:
        val_4byte -= 2**32
    print(f"4バイト符号付き (下位): {val_4byte}")
    
    # 上位4バイトを使用
    val_4byte_upper = int(hex_val[:8], 16)
    if val_4byte_upper >= 2**31:
        val_4byte_upper -= 2**32
    print(f"4バイト符号付き (上位): {val_4byte_upper}")
    
    # 2バイト符号付き
    val_2byte = int(hex_val[-4:], 16)  # 下位2バイト
    if val_2byte >= 2**15:
        val_2byte -= 2**16
    print(f"2バイト符号付き (下位): {val_2byte}")
    
    # -800を16進数に変換して確認
    print(f"\n-800の16進表現:")
    print(f"2バイト: {(-800) & 0xFFFF:04X}")
    print(f"4バイト: {(-800) & 0xFFFFFFFF:08X}")
    
    print(f"\n-1900の16進表現:")
    print(f"2バイト: {(-1900) & 0xFFFF:04X}")
    print(f"4バイト: {(-1900) & 0xFFFFFFFF:08X}")

def search_coordinate_values_in_decoded():
    """
    復号化されたテキスト内で-800や-1900に対応する16進数を探す
    """
    print("\n=== 座標値検索 ===")
    
    # -800と-1900の16進表現
    val_800_2byte = (-800) & 0xFFFF  # FCE0
    val_1900_2byte = (-1900) & 0xFFFF  # F894
    val_800_4byte = (-800) & 0xFFFFFFFF  # FFFFFCE0
    val_1900_4byte = (-1900) & 0xFFFFFFFF  # FFFFF894
    
    print(f"-800の16進: 2バイト={val_800_2byte:04X}, 4バイト={val_800_4byte:08X}")
    print(f"-1900の16進: 2バイト={val_1900_2byte:04X}, 4バイト={val_1900_4byte:08X}")
    
    result = deobfuscate_password(obfuscated_text)
    
    # これらの値が復号化テキストに含まれているか確認
    if "FCE0" in result.upper():
        print("FCE0 (-800の2バイト表現) が見つかりました！")
    if "F894" in result.upper():
        print("F894 (-1900の2バイト表現) が見つかりました！")
    if "FFFFFCE0" in result.upper():
        print("FFFFFCE0 (-800の4バイト表現) が見つかりました！")
    if "FFFFF894" in result.upper():
        print("FFFFF894 (-1900の4バイト表現) が見つかりました！")

# 新しい分析を実行
try_different_interpretations()
search_coordinate_values_in_decoded()
