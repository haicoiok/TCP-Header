# TCP Header
### Lấy mẫu gói tin

- Đơn giản nhất, ta có thể mở Terminal với lệnh ping liên tục ping 8.8.8.8. Song song, mở một Terminal thứ hai dùng tcpdump capture 2 gói tin ICMP request và ICMP response để làm mẫu.
- Kết quả có thể như sau:

![](https://user-images.githubusercontent.com/44948247/94233908-e4c84800-ff32-11ea-8e1c-30ad9920a7cd.PNG)
- Ta bắt được 2 packets, thông tin về packet đầu tiên được bắt đầu và kết thúc:

![](https://user-images.githubusercontent.com/44948247/94233912-e5f97500-ff32-11ea-81ea-28058b080471.PNG)

- Với tcpdump option -vv, 2 dòng đầu tiên hiển thị tóm tắt các thông tin về IP header và ICMP header mà gói tin mang theo:

![](https://user-images.githubusercontent.com/44948247/94233913-e6920b80-ff32-11ea-9b2c-c5bc69a5af02.PNG)

- Tham số -X giúp hiển thị data lấy được dưới dạng số hex và ASCII. Những giá trị này giúp ích khi sử dụng một số iptables modules như string, u32, bpf,…

![](https://user-images.githubusercontent.com/44948247/94233915-e72aa200-ff32-11ea-91df-200a21439918.PNG)

Tương tự, gói tin thứ 2 chứa tin nhắn "ICMP echo reply".
### PHÂN TÍCH IP HEADER
- Cấu trúc một IP header:

![](https://user-images.githubusercontent.com/44948247/94227440-b3488000-ff24-11ea-9a01-7f67a82899ac.png)
##### Chúng ta bắt đầu tập phân tích từ Field đầu tiên của IP Header:
- Version (4 bits đầu)
![](https://user-images.githubusercontent.com/44948247/94227442-b479ad00-ff24-11ea-9d5e-62fb68397089.jpg)
Giá trị 0x4 cho biết đây là một gói tin IPv4. Nếu là IPv6 sẽ có giá trị 0x6.
> Liệu có bất thường nếu một ngày server nhận hàng loạt packets có giá trị khác?

##### IHL (Internet Header Length) 4 bits.
![](https://user-images.githubusercontent.com/44948247/94227444-b5124380-ff24-11ea-992b-c52d51bcb747.jpg)
Giá trị 0x5 cho biết độ dài của IP Header là 5 words (Mỗi word 32 bits), do đó:
- IP header có độ dài 20 bytes, bắt đầu và kết thúc "4500 0054 6c20 4000 4001 fcb3 c0a8 011d 0808 0808". Phần còn lại là data (gói ICMP).
- 20 bytes là độ dài tối thiểu của một IP header, vậy packet này không có IP options.
> Dịch vụ của bạn có sử dụng thêm IP options?

##### TOS (Type of Service) 8 bits.
![](https://user-images.githubusercontent.com/44948247/94227445-b5aada00-ff24-11ea-8644-779affb0f6e8.jpg)
Field TOS của gói echo-request bằng 0x00, gói tin echo-reply từ Google 8.8.8.8 bằng "0x20".
> - 0x20 tương ứng |0010 0000|. Field TOS được bật bit thứ 5 có ý nghĩa gì?
- Ứng dụng của bạn khi trao đổi dữ liệu có sử dụng bit đặc biệt nào không? Giá trị thường thấy là bao nhiêu?

##### Total length 16 bits.
![](https://user-images.githubusercontent.com/44948247/94227448-b6437080-ff24-11ea-8924-78953172f6ab.jpg)
Tổng độ dài packet (Tính cả IP Header và Data mang theo) là 0x0054 hay 84 bytes. Ta biết IP Header dài 20 byptes, vậy Data phía sau dài 84 – 20 = 64 bytes.
##### Identification 16 bits.
![](https://user-images.githubusercontent.com/44948247/94227450-b6437080-ff24-11ea-8279-8a74344a9d6d.jpg)
Định danh gói tin, mỗi gói tin được đánh số duy nhất. Gói một có id 0x6c20 hay id 27608. Mặt định khi build gói tin, HĐH đánh số packet sau tăng một đơn vị so với packet trước đó.
> Trường hợp gói tin reply từ Google có id cố định bằng 0x0000 (không) là một giá trị đặc biệt của máy chủ Google. Một số công cụ (hoặc lập trình) crafted packets tạo ra traffic DoS với các gói tin có id cố định, đây cũng là một dấu hiệu nhận biết để phân biệt traffic tấn công.

##### IP fragmentation fieds 16 bit.
![](https://user-images.githubusercontent.com/44948247/94227451-b7749d80-ff24-11ea-957b-07d8fd387931.jpg)
4 bytes tiếp theo cung cấp thông tin: liệu gói tin có phân mảnh (fragment). Nếu có phân mảnh xảy ra, HĐH sẽ thực hiện quá trình hợp nhất (reassembly) các gói tin bị phân mảnh lại với nhau, dựa theo giá trị offset trên từng gói.

Theo qui định, 1 bit unused đầu tiên không được sử dụng và thường set về 0.
1 bit flag DF (Don’t fragment).
1 bit fag MF (More fragments).
13 bits còn lại, giá trị offset. Offset thường chỉ có giá trị nếu Datagram có phân mảnh.
Trong hai gói tin mẫu:
- Gói tin thứ nhất: 0x4000 tương đương |0100 0000 0000 0000|, cho biết bit "DF" được bật, không có More fragments và offset bằng không.
- Gói tin thứ hai: 0x0000 |0000 0000 0000 0000| không có bit flag nào bật, offset bằng không.
> IP fragmentation là một chủ đề rộng và có nhiều dạng tấn công khai thác xoay quanh(Teardrop, TCP Header Fragments…).
Kiến thức fragmentation cũng giúp ta phân biệt được những crafted packets không được build theo đúng chuẩn, gói không phân mảnh nhưng offset khác 0 là một ví dụ.

##### TTL (Time to Live) 8 bits.
![](https://user-images.githubusercontent.com/44948247/94227453-b8a5ca80-ff24-11ea-9e88-e0bbac842310.jpg)
Mặc định khi build gói tin, giá trị TTL khởi tạo của HĐH Linux là 64, HĐH Windows là 128, các thiết bị Cisco là 254,… Đồng thời, khi truyền đi trên Internet, giá trị TTL được giảm đi 1 khi đi qua một hop (router, modem, host,.. các thiết bị layer 3).
- Gói tin thứ nhất có TTL 0x40 hay 64, được tạo bởi máy tính cá nhân HĐH Linux, được captured trên card mạng khi chưa đi qua hop nào. Do đó, giá trị TTL 64 và chưa giảm.
- Gói tin thứ hai có TTL 0x37 hay 55, bạn có thể dự đoán tại server 8.8.8.8 gói tin được khởi tạo với TTL 64, vào internet về đến máy tính của tôi đã truyền qua qua 9 hops khác nhau.
> Dựa vào TTL, bạn có thể đoán một gói tin tạo ra bởi HĐH Windows hay Linux.
Một số công cụ tấn công DDoS tạo ra gói tin cố định hoặc giá trị bất thường, bạn có thể dựa vào TTL để phân biệt được traffic tấn công.

##### Protocol 8 bits.
![](https://user-images.githubusercontent.com/44948247/94227456-b93e6100-ff24-11ea-8516-bdf16c967774.jpg)
Giá trị 0x01 cho biết giao thức lớp trên là ICMP – hay gói tin mang theo một tin nhắn ICMP phía sau.
> Giao thức lớp trên: TCP có giá trị 0x06, UDP có giá trị 0x11.

##### Header checksum 16 bits.
![](https://user-images.githubusercontent.com/44948247/94227458-b9d6f780-ff24-11ea-9a9e-daf1af4d0c80.jpg)
2 bytes tiếp theo là giá trị checksum của IP header và IP options.
##### Source IP address 32 bits.
![](https://user-images.githubusercontent.com/44948247/94227460-b9d6f780-ff24-11ea-9e47-eb1e18fe7cf9.jpg)
4 bytes 0xc0a8011d lưu địa chỉ source IP của gói tin.
Cụ thể, 0xc0a8011d chia thành 4 octecs | c8 | a9 | 01 | 1d | tương đương thập phân |192 | 168 | 1 | 29|.
Vậy gói tin này được tạo từ máy tính của tôi với source IP 192.168.1.29.
Destination IP address 32 bits.
##### Destination IP address 32 bits.
![](https://user-images.githubusercontent.com/44948247/94227461-ba6f8e00-ff24-11ea-89d9-9054b7ffb8a3.jpg)
4 bytes lưu địa chỉ đích của gói tin. Với giá trị 0x08080808, ta dễ dàng nhận biết gói tin được gửi đến địa chỉ 8.8.8.8 của Google.
##### IP data.
![](https://user-images.githubusercontent.com/44948247/94227462-bb082480-ff24-11ea-801a-856346b000d8.jpg)
Thông qua IP Header Length, chúng ta đã biết phần Header của gói tin IP đang xét dài 20 bytes và không có IP Options. Chúng ta đã xét đủ từ byte đầu tiên đến byte thứ 20 của IP Header.

Phần còn lại dài 64 bytes là data mà gói IP đang mang. Thông qua field Protocol bằng 0x01 ta cũng biết được thêm rằng data phía sau là một gói ICMP.

Phân tích chi tiết về gói tin ICMP nằm ngoài phạm vi bài viết, đọc giả có thể tự mình tìm hiểu và phân tích ICMP header một cách tương tự.

### End
