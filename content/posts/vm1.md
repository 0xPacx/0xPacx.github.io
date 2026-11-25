---
tags:
  - Malware
title: "MalwareTech VM1 Challenge: Sanallaştırma Üzerine..."
date: 2026-11-25
draft:
author: Pacx
---

## MalwareTech VM1 Challenge: Sanallaştırma Üzerine... 

Zararlı yazılımlar bazen analizi zorlaştırmak için standart `x86_64` komutları yerine kendi içlerinde küçük bir VM kurarlar. Bu yapıda kritik veriler doğrudan çözülmez; bellekteki `bytecode` dizisi, programın kendi `dispatcher` fonksiyonu tarafından yorumlanarak adım adım işlenir.

Bu yazıda MalwareTech VM1 challenge'ını statik analizle nasıl çözdüğümü anlatacağım.

![Img](/assets/img/vm1.1.png)
### 1. entry0 Fonksiyonu 

Analize `entry0` (`0x1400019b0`) fonksiyonundan başladığımızda programın tüm yaşam döngüsünü tek blokta görebiliyoruz:

Program ilk olarak `GetProcessHeap` ile mevcut process `heap` alanının handle değerini alıyor ve `HeapAlloc` çağrısına 507 byte vererek bellekte dinamik bir alan ayırıyor. Ayrılan bu belleğin başlangıç adresi `data.140003890` işaretçisine kaydediliyor. Hemen ardından kaynak adresi (`rsi`) `data.140003100`, hedef adresi (`rdi`) `data.140003890` ve boyutu (`ecx`) `0x1fb`(507 byte) olarak ayarlayıp `rep movsb` komutuyla binary içine gömülü ham veriyi bu `heap` alanına kopyalıyor. Program çalışma boyunca bu `heap` bloğunu kendi RAM alanı olarak kullanıyor.

Kopyalama tamamlandıktan sonra VM motorunu başlatan `fcn.140001900` fonksiyonu çağrılıyor. Bu fonksiyon görevini bitirip döndüğünde ise `data.140003890` adresindeki çözülmüş verinin `md5_hash` fonksiyonuyla özeti alınıyor ve `MessageBoxA` ile ekrana basılıyor.

### 2. VM Döngüsü (`fcn.140001900`)

`fcn.140001900` fonksiyonunun graph görünümüne geçtiğimizde, RAM içindeki `bytecode` komutlarını sırayla okuyup işleyen ana döngüyü görüyoruz:

![Img](/assets/img/vm1.2.png)


Fonksiyonun girişinde `var_18h` yerel değişkeni `0x00` olarak sıfırlanıyor; bu değişken VM'in Instruction Pointer'ı olarak kullanılıyor. Döngü bloğuna (`0x140001914`) girildiğinde her turda `var_18h` değerine `0xff` (255) ekleniyor ve `data.140003890` taban adresinin üzerine bu offset eklenerek (`[rcx + rax*1]`) bellekten veri okunuyor. Bu da bize RAM'in ilk 255 byte'lık kısmının şifreli veriye ve çalışma alanına ayrıldığını, çalıştırılacak `bytecode` dizisinin ise `0xff` offset'inden itibaren başladığını gösteriyor.

Döngünün her adımında bu yöntemle bellekten ardışık 3 byte çekiliyor ve her okumadan sonra `var_18h` değeri `inc al` ile 1 artırılıyor. Okunan ilk byte `var_ch`, ikinci byte `var_10h`, üçüncü byte ise `var_14h` değişkenine alınıyor. Ardından bu üç değer sırasıyla `ecx`, `edx` ve `r8d` register'larına yüklenerek `fcn.140001860` fonksiyonuna argüman olarak gönderiliyor. Çağrı sonrasında `test eax, eax` ve `jnz` kontrolleriyle dönüş değerine bakılıyor; fonksiyon `0` dışında bir değer döndürdüğü sürece döngü bir sonraki 3 byte'ı okumak üzere başa sarıyor.

### 3. Dispatcher Fonksiyonu (`fcn.140001860`)

Önceki döngüde RAM'den okunan 3 byte, bu fonksiyona sırasıyla `arg1`, `arg2` ve `arg3` olarak gönderiliyor. Fonksiyonun en üstündeki kutuda bu üç argüman yerel değişkenlere (`var_8h`, `var_10h`, `var_18h`) alınıyor ve ilk gelen `arg1` değerine göre 4 farklı kola ayrılıyor:

![3. Img](/assets/img/vm1.3.png)

- `arg1 == 0x01` (`0x14000188c`): `arg2` değerini indeks olarak kullanıp RAM'in (`data.140003890`) o sırasına `arg3` değerini yazıyor (`RAM[arg2] = arg3`). Ardından en alttaki `mov eax, 0x01` kutusuna giderek döngünün devam etmesini sağlıyor.
    
- `arg1 == 0x02` (`0x1400018a2`): RAM'in `arg2` indeksindeki byte'ı okuyor ve `data.140003480` adresindeki tek byte'lık alana kopyalıyor (`data.140003480 = RAM[arg2]`). Bu global adres VM'in tek `register` alanı olarak kullanılıyor. İşlem bitince yine `eax = 1` döndürüyor.

- `arg1 == 0x03` (`0x1400018ba`): `data.140003480` içine daha önce yüklenen `register` değerini alıyor ve RAM'in `arg2` indeksindeki byte ile `XOR` işlemine sokuyor. Çıkan sonucu tekrar RAM'in aynı indeksine yazıyor ve `eax = 1` döndürüyor.
    
- Diğer değerler (`0x1400018e4`): `arg1` bu üç değerden biri değilse akış `xor eax, eax` kutusuna düşüyor ve `0` döndürülerek VM döngüsü sonlandırılıyor.

### 4. Memory Dump ve Python ile Çözüm

VM'in tüm çalışma mantığını çözdüğümüze göre binary'yi çalıştırmaya gerek kalmadan statik olarak `flag` değerini çıkarabiliriz. Öncelikle Ghidra üzerinden şifreli veriyi ve `bytecode` bloğunu dışarı almamız gerekiyor:

- Ghidra'da Listing penceresinden `data.140003100` (`DAT_140003100`) adresine gidiyoruz.
    
- Başlangıç adresinden itibaren **Select -> Bytes** kısmından `507` byte boyutunda veri bloğu seçiyoruz.
    
- Sağ tıklayıp **Copy Special -> Byte String** seçeneğiyle ham hex verisini kopyalıyoruz.
    

Kopyaladığımız bu 507 byte'lık hex dizisini, yukarıda çıkardığımız `0x01`, `0x02` ve `0x03` kurallarını taklit eden Python script'ine verdiğimizde, önce `0x01` komutları şifre çözme anahtarlarını RAM'in ilgili adreslerine yerleştiriyor, ardından `0x02` ve `0x03` komutları bu anahtarları `register` üzerinden geçirerek belleğin başındaki şifreli byte'ları `XOR` ile çözüyor. Döngü tamamlandığında FLAG ortaya çıkıyor.

![ımg](/assets/img/vm1.4.png)

Yazdığım Python koduna GitHub repom üzerinden ulaşabilirsiniz: [GitHub link](https://github.com/0xPacx/vm1_ctf)