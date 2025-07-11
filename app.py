import streamlit as st
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import math
import struct
import random
import hashlib
import zlib
import base64
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# --- Constants ---
SALT_SIZE = 16
KEY_SIZE = 32
AES_BLOCK_SIZE = 16
MAGIC_BYTES = b'STGA'
HEADER_FORMAT = f'!{len(MAGIC_BYTES)}s'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# --- Core Steganography Functions ---
def get_aes_key(password: str, salt: bytes) -> bytes:
    """Generate AES key from password and salt"""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=1000000)

def encrypt_message(data: bytes, password: str) -> bytes:
    """Encrypt data using AES-256-CBC"""
    salt = get_random_bytes(SALT_SIZE)
    key = get_aes_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    padded_data = pad(data, AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_data)
    return salt + cipher.iv + ciphertext

def decrypt_message(encrypted_data: bytes, password: str) -> bytes:
    """Decrypt data using AES-256-CBC"""
    try:
        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE:SALT_SIZE + AES_BLOCK_SIZE]
        ciphertext = encrypted_data[SALT_SIZE + AES_BLOCK_SIZE:]
        key = get_aes_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded_data, AES_BLOCK_SIZE)
    except (ValueError, KeyError):
        raise ValueError("Mật khẩu không đúng hoặc dữ liệu bị lỗi")

def generate_pixel_sequence(width: int, height: int, password: str) -> list:
    """Generate pseudo-random pixel sequence based on password"""
    seed = int(hashlib.sha256(password.encode()).hexdigest(), 16)
    random.seed(seed)
    locations = [(x, y) for y in range(height) for x in range(width)]
    random.shuffle(locations)
    return locations

def message_to_binary(message: bytes) -> str:
    """Convert message to binary string"""
    return ''.join([format(byte, '08b') for byte in message])

def binary_to_bytes(binary_string: str) -> bytes:
    """Convert binary string to bytes"""
    if len(binary_string) % 8 != 0:
        raise ValueError("Độ dài chuỗi nhị phân phải chia hết cho 8")
    
    bytes_data = bytearray()
    for i in range(0, len(binary_string), 8):
        byte_chunk = binary_string[i:i+8]
        bytes_data.append(int(byte_chunk, 2))
    
    return bytes(bytes_data)

def hide_message(image: Image.Image, secret_message: str, password: str, 
                use_compression: bool = True, use_encryption: bool = True) -> Image.Image:
    """Hide message in image using adaptive steganography"""
    img_array = np.array(image)
    height, width, _ = img_array.shape
    
    # Process message
    message_data = secret_message.encode('utf-8')
    
    # Compression
    if use_compression:
        message_data = zlib.compress(message_data)
    
    # Encryption
    if use_encryption:
        message_data = encrypt_message(message_data, password)
    
    # Create header with flags
    flags = (use_compression << 1) | use_encryption
    header = struct.pack(HEADER_FORMAT, MAGIC_BYTES) + struct.pack('!IB', len(message_data), flags)
    
    data_to_hide = header + message_data
    binary_data = message_to_binary(data_to_hide)
    
    # Check capacity
    max_capacity = width * height * 3
    if len(binary_data) > max_capacity:
        raise ValueError(f"Thông điệp quá lớn. Tối đa: {max_capacity // 8} bytes")
    
    # Generate pixel sequence
    pixel_sequence = generate_pixel_sequence(width, height, password)
    
    # Hide data
    data_index = 0
    for x, y in pixel_sequence:
        if data_index >= len(binary_data):
            break
            
        pixel = img_array[y, x]
        for i in range(3):  # RGB channels
            if data_index < len(binary_data):
                pixel[i] = pixel[i] & ~1 | int(binary_data[data_index])
                data_index += 1
        img_array[y, x] = pixel
    
    return Image.fromarray(img_array)

def reveal_message(image: Image.Image, password: str) -> str:
    """Reveal hidden message from image"""
    img_array = np.array(image)
    height, width, _ = img_array.shape
    
    # Generate same pixel sequence
    pixel_sequence = generate_pixel_sequence(width, height, password)
    pixel_iterator = iter(pixel_sequence)
    
    # Extract header
    header_bit_len = (HEADER_SIZE + 5) * 8  # +5 for length and flags
    binary_header = ""
    
    while len(binary_header) < header_bit_len:
        try:
            x, y = next(pixel_iterator)
            pixel = img_array[y, x]
            for i in range(3):
                if len(binary_header) < header_bit_len:
                    binary_header += str(pixel[i] & 1)
        except StopIteration:
            raise ValueError("Không đủ dữ liệu để trích xuất header")
    
    # Parse header
    header_bytes = binary_to_bytes(binary_header)
    magic = struct.unpack(HEADER_FORMAT, header_bytes[:HEADER_SIZE])[0]
    data_len, flags = struct.unpack('!IB', header_bytes[HEADER_SIZE:HEADER_SIZE+5])
    
    if magic != MAGIC_BYTES:
        raise ValueError("Không tìm thấy dữ liệu StegaSafe hoặc mật khẩu sai")
    
    use_compression = bool(flags & 2)
    use_encryption = bool(flags & 1)
    
    # Extract data
    binary_data = ""
    data_bit_len = data_len * 8
    
    while len(binary_data) < data_bit_len:
        try:
            x, y = next(pixel_iterator)
            pixel = img_array[y, x]
            for i in range(3):
                if len(binary_data) < data_bit_len:
                    binary_data += str(pixel[i] & 1)
        except StopIteration:
            raise ValueError("Dữ liệu không đầy đủ")
    
    # Process extracted data
    extracted_data = binary_to_bytes(binary_data)
    
    # Decrypt if needed
    if use_encryption:
        extracted_data = decrypt_message(extracted_data, password)
    
    # Decompress if needed
    if use_compression:
        extracted_data = zlib.decompress(extracted_data)
    
    return extracted_data.decode('utf-8')

def calculate_psnr(original_img: Image.Image, stego_img: Image.Image) -> float:
    """Calculate Peak Signal-to-Noise Ratio"""
    original_arr = np.array(original_img).astype(np.float64)
    stego_arr = np.array(stego_img).astype(np.float64)
    mse = np.mean((original_arr - stego_arr) ** 2)
    if mse == 0:
        return float('inf')
    max_pixel_value = 255.0
    return 20 * math.log10(max_pixel_value / math.sqrt(mse))

def calculate_ssim(original_img: Image.Image, stego_img: Image.Image) -> float:
    """Calculate Structural Similarity Index"""
    original_arr = np.array(original_img).astype(np.float64)
    stego_arr = np.array(stego_img).astype(np.float64)
    
    mu1 = np.mean(original_arr)
    mu2 = np.mean(stego_arr)
    sigma1_sq = np.var(original_arr)
    sigma2_sq = np.var(stego_arr)
    sigma12 = np.cov(original_arr.flatten(), stego_arr.flatten())[0, 1]
    
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    
    ssim = ((2 * mu1 * mu2 + c1) * (2 * sigma12 + c2)) / ((mu1**2 + mu2**2 + c1) * (sigma1_sq + sigma2_sq + c2))
    return ssim

def analyze_histogram(original_img: Image.Image, stego_img: Image.Image):
    """Analyze histogram differences"""
    original_arr = np.array(original_img)
    stego_arr = np.array(stego_img)
    
    # Calculate histograms for each channel
    channels = ['Red', 'Green', 'Blue']
    colors = ['red', 'green', 'blue']
    
    fig = make_subplots(
        rows=2, cols=3,
        subplot_titles=('Original Red', 'Original Green', 'Original Blue',
                       'Stego Red', 'Stego Green', 'Stego Blue'),
        vertical_spacing=0.1
    )
    
    for i, (channel, color) in enumerate(zip(channels, colors)):
        # Original histogram
        hist_orig, bins = np.histogram(original_arr[:,:,i], bins=256, range=(0, 256))
        fig.add_trace(
            go.Scatter(x=bins[:-1], y=hist_orig, mode='lines', name=f'Original {channel}',
                      line=dict(color=color, width=2)),
            row=1, col=i+1
        )
        
        # Stego histogram
        hist_stego, _ = np.histogram(stego_arr[:,:,i], bins=256, range=(0, 256))
        fig.add_trace(
            go.Scatter(x=bins[:-1], y=hist_stego, mode='lines', name=f'Stego {channel}',
                      line=dict(color=color, width=2)),
            row=2, col=i+1
        )
    
    fig.update_layout(
        height=600,
        title_text="Histogram Comparison Analysis",
        showlegend=False
    )
    
    return fig

def create_difference_map(original_img: Image.Image, stego_img: Image.Image):
    """Create visual difference map"""
    original_arr = np.array(original_img).astype(np.float64)
    stego_arr = np.array(stego_img).astype(np.float64)
    
    # Calculate absolute difference
    diff = np.abs(original_arr - stego_arr)
    diff_gray = np.mean(diff, axis=2)
    
    # Enhance differences for visualization
    enhanced_diff = diff_gray * 10
    enhanced_diff = np.clip(enhanced_diff, 0, 255)
    
    fig = go.Figure(data=go.Heatmap(
        z=enhanced_diff,
        colorscale='Viridis',
        showscale=True,
        colorbar=dict(title="Pixel Difference (Enhanced)")
    ))
    
    fig.update_layout(
        title="Pixel Difference Heatmap (Enhanced x10)",
        xaxis_title="Width",
        yaxis_title="Height",
        height=500
    )
    
    return fig

def validate_fernet_key(key_input):
    """Validate Fernet key format"""
    try:
        if isinstance(key_input, str):
            key_input = key_input.strip().encode("utf-8")
        decoded = base64.urlsafe_b64decode(key_input)
        if len(decoded) != 32:
            raise ValueError("Khóa Fernet không đúng định dạng")
        return key_input
    except Exception as e:
        raise ValueError(f"Khóa không hợp lệ: {str(e)}")

# --- Streamlit UI ---
st.set_page_config(
    page_title="StegaSafe Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem 1rem;
        border-radius: 15px;
        text-align: center;
        color: white;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    }
    
    .main-header h1 {
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
        font-weight: 700;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #4CAF50, #45a049);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        text-align: center;
        margin: 1rem 0;
    }
    
    .success-card {
        background: linear-gradient(135deg, #4CAF50, #45a049);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
    }
    
    .math-formula {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #007bff;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ StegaSafe Pro</h1>
    <p>Professional Steganography Platform with Advanced Analysis</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("### 📊 Thông tin")
    st.info("""
    **StegaSafe Pro** - Công cụ steganography chuyên nghiệp với:
    
    ✅ Mã hóa AES-256  
    ✅ Nén dữ liệu  
    ✅ Phân tích PSNR/SSIM  
    ✅ Biểu đồ histogram  
    ✅ Heatmap khác biệt  
    """)
    
    st.markdown("### 🔧 Tính năng")
    st.markdown("""
    - **Bảo mật cao**: Mã hóa AES-256
    - **Tối ưu dung lượng**: Nén zlib
    - **Phân tích toán học**: PSNR, SSIM
    - **Trực quan hóa**: Biểu đồ so sánh
    """)

# Main tabs
tab1, tab2, tab3, tab4 = st.tabs(["🔒 Giấu tin", "🔑 Giải mã", "📊 Phân tích", "📚 Lý thuyết"])

# Hide Message Tab
with tab1:
    st.markdown("## 🔐 Giấu thông điệp vào ảnh")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### 📁 Tải ảnh gốc")
        
        uploaded_image = st.file_uploader(
            "Chọn ảnh (PNG, BMP, JPG)",
            type=['png', 'bmp', 'jpg'],
            help="Khuyến nghị PNG hoặc BMP"
        )
        
        if uploaded_image:
            original_image = Image.open(uploaded_image).convert("RGB")
            st.image(original_image, caption="Ảnh gốc", use_column_width=True)
            
            width, height = original_image.size
            st.info(f"📏 Kích thước: {width}x{height}")
            max_capacity = (width * height * 3) // 8
            st.info(f"📊 Dung lượng tối đa: ~{max_capacity} bytes")
    
    with col2:
        if uploaded_image:
            st.markdown("### ⚙️ Cấu hình")
            
            # Method selection
            method = st.selectbox(
                "Phương thức:",
                ["Adaptive", "Fernet Encryption", "Simple LSB"]
            )
            
            # Message input
            secret_message = st.text_area(
                "Thông điệp:",
                height=100,
                placeholder="Nhập nội dung bí mật..."
            )
            
            # Password input
            password = st.text_input(
                "Mật khẩu:",
                type="password",
                placeholder="Nhập mật khẩu..."
            )
            
            # Options
            col_opt1, col_opt2 = st.columns(2)
            with col_opt1:
                use_compression = st.checkbox("Nén dữ liệu", value=True)
            with col_opt2:
                use_encryption = st.checkbox("Mã hóa", value=True)
            
            # Process button
            if st.button("🚀 Giấu tin", type="primary", use_container_width=True):
                if not secret_message or not password:
                    st.warning("Vui lòng nhập đầy đủ thông tin")
                else:
                    try:
                        with st.spinner("Đang xử lý..."):
                            if method == "Adaptive (Khuyến nghị)":
                                stego_image = hide_message(original_image, secret_message, password, 
                                                         use_compression, use_encryption)
                            elif method == "Fernet Encryption":
                                # Simple Fernet implementation
                                key = Fernet.generate_key()
                                cipher = Fernet(key)
                                encrypted_msg = cipher.encrypt(secret_message.encode())
                                stego_image = hide_message(original_image, encrypted_msg.decode('latin-1'), 
                                                         password, False, False)
                                st.session_state.fernet_key = key
                            else:  # Simple LSB
                                stego_image = hide_message(original_image, secret_message, password, 
                                                         False, False)
                            
                            st.session_state.stego_image = stego_image
                            st.session_state.original_image = original_image
                            st.session_state.method = method
                            st.success("✅ Hoàn tất!")
                    except Exception as e:
                        st.error(f"❌ Lỗi: {e}")

    # Display results only in current tab
    if 'stego_image' in st.session_state:
        st.divider()
        st.markdown("## 📊 Kết quả")
        
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            st.image(st.session_state.original_image, caption="Ảnh gốc", use_column_width=True)
        
        with col2:
            st.image(st.session_state.stego_image, caption="Ảnh stego", use_column_width=True)
        
        with col3:
            st.markdown("### 📥 Tải xuống")
            buf = BytesIO()
            st.session_state.stego_image.save(buf, format="PNG")
            byte_data = buf.getvalue()
            
            st.download_button(
                label="📥 Tải Stego Image",
                data=byte_data,
                file_name="stego_image.png",
                mime="image/png",
                use_container_width=True
            )
            
            if 'fernet_key' in st.session_state:
                st.download_button(
                    label="🔑 Tải Fernet Key",
                    data=st.session_state.fernet_key,
                    file_name="fernet_key.key",
                    use_container_width=True
                )

# Reveal Message Tab
with tab2:
    st.markdown("## 🔓 Giải mã thông điệp")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### 📁 Tải ảnh stego")
        
        stego_upload = st.file_uploader(
            "Chọn ảnh stego (PNG, BMP)",
            type=['png', 'bmp'],
            key="decode_upload"
        )
        
        if stego_upload:
            stego_image_decode = Image.open(stego_upload).convert("RGB")
            st.image(stego_image_decode, caption="Ảnh stego", use_column_width=True)
    
    with col2:
        if stego_upload:
            st.markdown("### 🔍 Giải mã")
            
            decode_method = st.selectbox(
                "Phương thức giải mã:",
                ["Adaptive", "Fernet Encryption", "Simple LSB"],
                key="decode_method"
            )
            
            password_decode = st.text_input(
                "Mật khẩu:",
                type="password",
                key="decode_password"
            )
            
            if decode_method == "Fernet Encryption":
                fernet_key_input = st.text_input(
                    "Fernet Key:",
                    placeholder="Nhập key hoặc upload file key",
                    key="fernet_key_input"
                )
                
                key_file = st.file_uploader("Hoặc upload file key", type=['key'])
                if key_file:
                    fernet_key_input = key_file.read().decode()
            
            if st.button("🔍 Giải mã", type="primary", use_container_width=True):
                if not password_decode:
                    st.warning("Vui lòng nhập mật khẩu")
                else:
                    try:
                        with st.spinner("Đang giải mã..."):
                            if decode_method == "Fernet Encryption":
                                if not fernet_key_input:
                                    st.error("Vui lòng nhập Fernet key")
                                else:
                                    key = validate_fernet_key(fernet_key_input)
                                    encrypted_msg = reveal_message(stego_image_decode, password_decode)
                                    cipher = Fernet(key)
                                    revealed_message = cipher.decrypt(encrypted_msg.encode('latin-1')).decode()
                            else:
                                revealed_message = reveal_message(stego_image_decode, password_decode)
                            
                            st.markdown("""
                            <div class="success-card">
                                <h3>🎉 Giải mã thành công!</h3>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            st.markdown("### 📝 Thông điệp:")
                            st.text_area(
                                "Nội dung:",
                                value=revealed_message,
                                height=200,
                                disabled=True,
                                key="revealed_message"
                            )
                            
                            st.info(f"📊 Độ dài: {len(revealed_message)} ký tự")
                            
                    except Exception as e:
                        st.error(f"❌ Lỗi: {e}")

# Analysis Tab
with tab3:
    st.markdown("## 📊 Phân tích chất lượng và bảo mật")
    
    if 'stego_image' in st.session_state and 'original_image' in st.session_state:
        # Quality metrics
        psnr_value = calculate_psnr(st.session_state.original_image, st.session_state.stego_image)
        ssim_value = calculate_ssim(st.session_state.original_image, st.session_state.stego_image)
        
        # Metrics display
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>PSNR Score</h3>
                <h2>{psnr_value:.2f} dB</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <h3>SSIM Score</h3>
                <h2>{ssim_value:.4f}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            quality = "Xuất sắc" if psnr_value > 40 else "Tốt" if psnr_value > 30 else "Khá"
            st.markdown(f"""
            <div class="metric-card">
                <h3>Chất lượng</h3>
                <h2>{quality}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        # Histogram analysis
        st.markdown("### 📈 Phân tích Histogram")
        histogram_fig = analyze_histogram(st.session_state.original_image, st.session_state.stego_image)
        st.plotly_chart(histogram_fig, use_container_width=True)
        
        # Difference heatmap
        st.markdown("### 🔥 Bản đồ nhiệt khác biệt")
        diff_fig = create_difference_map(st.session_state.original_image, st.session_state.stego_image)
        st.plotly_chart(diff_fig, use_container_width=True)
        
        # Statistical analysis
        st.markdown("### 📊 Phân tích thống kê")
        col1, col2 = st.columns(2)
        
        with col1:
            original_arr = np.array(st.session_state.original_image)
            stego_arr = np.array(st.session_state.stego_image)
            
            st.markdown("**Ảnh gốc:**")
            st.write(f"- Trung bình: {np.mean(original_arr):.2f}")
            st.write(f"- Độ lệch chuẩn: {np.std(original_arr):.2f}")
            st.write(f"- Min/Max: {np.min(original_arr)}/{np.max(original_arr)}")
        
        with col2:
            st.markdown("**Ảnh stego:**")
            st.write(f"- Trung bình: {np.mean(stego_arr):.2f}")
            st.write(f"- Độ lệch chuẩn: {np.std(stego_arr):.2f}")
            st.write(f"- Min/Max: {np.min(stego_arr)}/{np.max(stego_arr)}")
        
        # Difference statistics
        diff_arr = np.abs(original_arr.astype(float) - stego_arr.astype(float))
        st.markdown("**Khác biệt:**")
        st.write(f"- MSE: {np.mean(diff_arr**2):.6f}")
        st.write(f"- Khác biệt trung bình: {np.mean(diff_arr):.6f}")
        st.write(f"- Pixel thay đổi: {np.sum(diff_arr > 0)} / {diff_arr.size} ({100*np.sum(diff_arr > 0)/diff_arr.size:.2f}%)")
        
    else:
        st.info("Vui lòng thực hiện giấu tin trước để xem phân tích")

# Theory Tab
with tab4:
    st.markdown("## 📚 Lý thuyết và Công thức Toán học")
    
    st.markdown("### 🔢 Các thuật toán Steganography")
    
    # LSB Theory
    st.markdown("#### 1. Least Significant Bit (LSB)")
    st.markdown("""
    <div class="math-formula">
    <strong>Công thức LSB:</strong><br>
    Cho pixel gốc P và bit cần giấu b:<br>
    <code>P' = (P & 0xFE) | b</code><br><br>
    
    Trong đó:<br>
    • P': Pixel sau khi giấu tin<br>
    • 0xFE: Mask nhị phân 11111110<br>
    • b: Bit cần giấu (0 hoặc 1)<br>
    </div>
    """, unsafe_allow_html=True)
    
    # PSNR Theory
    st.markdown("#### 2. Peak Signal-to-Noise Ratio (PSNR)")
    st.latex(r'''
    PSNR = 10 \log_{10}\left(\frac{MAX_I^2}{MSE}\right) = 20 \log_{10}\left(\frac{MAX_I}{\sqrt{MSE}}\right)
    ''')
    st.markdown("""
    <div class="math-formula">
    <strong>Trong đó:</strong><br>
    • MAX_I: Giá trị pixel tối đa (255 cho ảnh 8-bit)<br>
    • MSE: Mean Squared Error<br><br>
    
    <strong>MSE được tính:</strong><br>
    </div>
    """, unsafe_allow_html=True)
    
    st.latex(r'''
    MSE = \frac{1}{mn}\sum_{i=0}^{m-1}\sum_{j=0}^{n-1}[I(i,j) - K(i,j)]^2
    ''')
    
    st.markdown("""
    <div class="math-formula">
    • I(i,j): Ảnh gốc tại pixel (i,j)<br>
    • K(i,j): Ảnh stego tại pixel (i,j)<br>
    • m,n: Kích thước ảnh<br>
    • PSNR > 40dB: Chất lượng xuất sắc<br>
    • PSNR 30-40dB: Chất lượng tốt<br>
    • PSNR < 30dB: Chất lượng khá
    </div>
    """, unsafe_allow_html=True)
    
    # SSIM Theory
    st.markdown("#### 3. Structural Similarity Index (SSIM)")
    st.latex(r'''
    SSIM(x,y) = \frac{(2\mu_x\mu_y + c_1)(2\sigma_{xy} + c_2)}{(\mu_x^2 + \mu_y^2 + c_1)(\sigma_x^2 + \sigma_y^2 + c_2)}
    ''')
    st.markdown("""
    <div class="math-formula">
    <strong>Trong đó:</strong><br>
    • μₓ, μᵧ: Trung bình cường độ pixel<br>
    • σₓ², σᵧ²: Phương sai cường độ pixel<br>
    • σₓᵧ: Hiệp phương sai<br>
    • c₁, c₂: Hằng số ổn định<br>
    • SSIM ∈ [0,1]: 1 là giống nhau hoàn toàn
    </div>
    """, unsafe_allow_html=True)
    
    # AES Encryption
    st.markdown("#### 4. Advanced Encryption Standard (AES-256)")
    st.markdown("""
    <div class="math-formula">
    <strong>Quá trình mã hóa AES:</strong><br>
    1. <strong>Key Expansion:</strong> Tạo round keys từ master key<br>
    2. <strong>Initial Round:</strong> AddRoundKey<br>
    3. <strong>Main Rounds (13 rounds):</strong><br>
    &nbsp;&nbsp;&nbsp;• SubBytes: Thay thế byte qua S-box<br>
    &nbsp;&nbsp;&nbsp;• ShiftRows: Dịch chuyển hàng<br>
    &nbsp;&nbsp;&nbsp;• MixColumns: Trộn cột<br>
    &nbsp;&nbsp;&nbsp;• AddRoundKey: XOR với round key<br>
    4. <strong>Final Round:</strong> SubBytes + ShiftRows + AddRoundKey
    </div>
    """, unsafe_allow_html=True)
    
    st.latex(r'''
    \text{SubBytes: } b'_{i,j} = S(b_{i,j})
    ''')
    st.latex(r'''
    \text{ShiftRows: } r_i \leftarrow r_i \ll i
    ''')
    st.latex(r'''
    \text{MixColumns: } c' = M \times c
    ''')
    
    # PBKDF2 Key Derivation
    st.markdown("#### 5. Password-Based Key Derivation Function 2 (PBKDF2)")
    st.latex(r'''
    PBKDF2(P, S, c, dkLen) = T_1 \| T_2 \| \ldots \| T_l
    ''')
    st.latex(r'''
    T_i = F(P, S, c, i) = U_1 \oplus U_2 \oplus \ldots \oplus U_c
    ''')
    st.latex(r'''
    U_1 = PRF(P, S \| INT(i)), \quad U_j = PRF(P, U_{j-1})
    ''')
    
    st.markdown("""
    <div class="math-formula">
    <strong>Trong đó:</strong><br>
    • P: Password<br>
    • S: Salt (16 bytes ngẫu nhiên)<br>
    • c: Iteration count (1,000,000)<br>
    • dkLen: Độ dài key mong muốn (32 bytes)<br>
    • PRF: Pseudo-random function (HMAC-SHA256)<br>
    • INT(i): 32-bit big-endian của i
    </div>
    """, unsafe_allow_html=True)
    
    # Steganography Capacity
    st.markdown("#### 6. Dung lượng Steganography")
    st.latex(r'''
    \text{Capacity} = W \times H \times C \times \text{BPP}
    ''')
    st.markdown("""
    <div class="math-formula">
    <strong>Trong đó:</strong><br>
    • W: Chiều rộng ảnh<br>
    • H: Chiều cao ảnh<br>
    • C: Số kênh màu (3 cho RGB)<br>
    • BPP: Bits per pixel (1 bit cho LSB)<br><br>
    
    <strong>Ví dụ:</strong> Ảnh 800x600 RGB<br>
    Capacity = 800 × 600 × 3 × 1 = 1,440,000 bits = 180,000 bytes
    </div>
    """, unsafe_allow_html=True)
    
    # Compression Theory
    st.markdown("#### 7. Nén dữ liệu Zlib (Deflate)")
    st.markdown("""
    <div class="math-formula">
    <strong>Thuật toán Deflate kết hợp:</strong><br>
    1. <strong>LZ77:</strong> Thay thế chuỗi lặp bằng con trỏ<br>
    2. <strong>Huffman Coding:</strong> Mã hóa entropy<br><br>
    
    <strong>LZ77 Distance-Length Pairs:</strong><br>
    (distance, length) thay cho chuỗi lặp<br><br>
    
    <strong>Huffman Coding:</strong><br>
    Ký tự xuất hiện nhiều → mã ngắn<br>
    Ký tự xuất hiện ít → mã dài
    </div>
    """, unsafe_allow_html=True)
    
    # Pseudo-random Sequence
    st.markdown("#### 8. Chuỗi vị trí Pseudo-random")
    st.latex(r'''
    \text{seed} = \text{SHA-256}(\text{password}) \bmod 2^{32}
    ''')
    st.markdown("""
    <div class="math-formula">
    <strong>Linear Congruential Generator (LCG):</strong><br>
    </div>
    """, unsafe_allow_html=True)
    
    st.latex(r'''
    X_{n+1} = (aX_n + c) \bmod m
    ''')
    st.markdown("""
    <div class="math-formula">
    • a = 1664525, c = 1013904223, m = 2³²<br>
    • Tạo chuỗi vị trí pixel (x,y) để giấu tin<br>
    • Fisher-Yates shuffle để trộn ngẫu nhiên
    </div>
    """, unsafe_allow_html=True)
    
    # Security Analysis
    st.markdown("### 🔒 Phân tích bảo mật")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        #### 🛡️ Điểm mạnh
        
        **1. Mã hóa AES-256:**
        - Chuẩn mã hóa quân sự
        - Key space: 2²⁵⁶ khả năng
        - Thời gian brute force: 10⁷⁷ năm
        
        **2. PBKDF2 với 1M iterations:**
        - Chống rainbow table
        - Tăng chi phí tấn công từ điển
        - Salt 16-byte ngẫu nhiên
        
        **3. Lộ trình ngẫu nhiên:**
        - Khó phát hiện pattern
        - Phân tán đều trên ảnh
        - Dựa trên mật khẩu
        """)
    
    with col2:
        st.markdown("""
        #### ⚠️ Điểm yếu tiềm ẩn
        
        **1. Thống kê histogram:**
        - LSB có thể thay đổi phân phối
        - Detectable qua Chi-square test
        - Cần phân tích kỹ hơn
        
        **2. Phụ thuộc mật khẩu:**
        - Weak password = weak security
        - Brute force nếu password đơn giản
        - Cần entropy cao
        
        **3. File format:**
        - JPEG compression phá hủy LSB
        - PNG/BMP lossless tốt hơn
        - Metadata có thể lộ thông tin
        """)
    
    # Comparison Table
    st.markdown("### 📊 So sánh các phương pháp")
    comparison_data = {
        'Phương pháp': ['LSB Simple', 'LSB + AES', 'LSB + AES + Random', 'Fernet + LSB'],
        'Bảo mật': ['⭐⭐', '⭐⭐⭐⭐', '⭐⭐⭐⭐⭐', '⭐⭐⭐⭐'],
        'Dung lượng': ['100%', '95%', '90%', '85%'],
        'Tốc độ': ['⭐⭐⭐⭐⭐', '⭐⭐⭐⭐', '⭐⭐⭐', '⭐⭐⭐⭐'],
        'Phát hiện': ['Dễ', 'Khó', 'Rất khó', 'Khó'],
        'Phục hồi': ['Dễ', 'Không thể', 'Không thể', 'Không thể']
    }
    
    st.table(comparison_data)
    
    # Mathematical Proofs
    st.markdown("### 🔬 Chứng minh toán học")
    
    st.markdown("#### PSNR và MSE")
    st.markdown("""
    <div class="math-formula">
    <strong>Chứng minh:</strong><br>
    Với ảnh 8-bit, MAX_I = 255<br>
    </div>
    """, unsafe_allow_html=True)
    
    st.latex(r'''
    \text{Nếu } MSE \to 0 \text{ thì } PSNR \to \infty
    ''')
    st.latex(r'''
    \text{Nếu } MSE = MAX_I^2 \text{ thì } PSNR = 0
    ''')
    
    st.markdown("""
    <div class="math-formula">
    Điều này chứng tỏ PSNR tỷ lệ nghịch với MSE và phản ánh chất lượng ảnh chính xác.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("#### Entropy và Nén")
    st.latex(r'''
    H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)
    ''')
    st.markdown("""
    <div class="math-formula">
    <strong>Shannon's Source Coding Theorem:</strong><br>
    Không thể nén dữ liệu xuống dưới entropy của nó mà không mất thông tin.<br>
    Zlib compression ratio phụ thuộc vào entropy của dữ liệu đầu vào.
    </div>
    """, unsafe_allow_html=True)

# Footer
st.divider()
st.markdown("""
<div style="text-align: center; color: #666; padding: 1rem;">
    <p>🛡️ <strong>StegaSafe Pro</strong> - Professional Steganography Platform</p>
    <p>Advanced Mathematical Analysis & Security Research Tool</p>
    <p>Developed with ❤️</p>
</div>
""", unsafe_allow_html=True)