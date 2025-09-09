import qrcode

qr = qrcode.make("RP2022-001")
qr.save("test_qr.png")