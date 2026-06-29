# Özellikler

## Veri Kümesi İşlemleri

Analiz için kullanılan veri kümelerini yönetin.

- **get_dataset_status**  
  Şu anda yüklü olan veri kümesinin durumunu alır.

- **list_datasets**  
  Analiz için kullanılabilir CSV veri kümelerini listeler.  
  Sayfalandırmayı destekler.

- **switch_dataset**  
  Etkin analiz veri kümesini belirtilen bir CSV dosyasına geçirir.

- **unload_dataset**  
  Geçerli `logs` tablosunu kaldırır.

- **dataset_profile**  
  Veri kümesinin bir özetini alır, şunları içerir:
  - toplam olay sayısı
  - zaman aralığı
  - en üst eğilimler

  Sayfalandırmayı destekler.

---

## Sorgu ve Arama

Günlük verilerinde arama yapın ve sorgulayın.

- **run_sql**  
  `logs` tablosuna karşı salt okunur bir `SELECT` sorgusu çalıştırır.  
  Yerleşik güvenlik kısıtlamaları içerir.

- **search_all_fields**  
  Tüm sütunlarda veya belirtilen sütunlarda anahtar kelime aramaları gerçekleştirir.  
  Sayfalandırmayı destekler.

- **get_event_detail**  
  Tek bir olayı genişletilmiş `Field / Value` biçiminde alır.  
  `RecordID` veya sorgu koşullarıyla aramayı destekler.

---

## Zaman Çizelgesi ve Analitik

Saldırı etkinliğini ve olay zaman çizelgelerini analiz edin.

- **analyze_mitre_tactics**  
  **MITRE ATT&CK taktiklerine** göre gruplandırılmış saldırı aşamalarının kronolojik analizini gerçekleştirir.

- **analyze_host_timeline**  
  Belirli bir ana bilgisayar için kronolojik olayları çıkarır.  
  **Ele geçirme zinciri takibi** için kullanışlıdır.

- **correlate_lateral_movement**  
  Belirtilen bir zaman aralığı içinde ana bilgisayarlar arasındaki yanal hareket etkinliğini ilişkilendirir.

- **summarize_events**  
  Günlük olaylarını belirtilen bir alana göre toplar.

- **summarize_by_time_window**  
  Olayları zaman aralığına göre sayar:
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  İsteğe bağlı filtreleme koşullarıyla `RuleTitle` oluşumlarının sıklığını toplar.

---

## Ayrıntı ve IOC Analizi

Günlük ayrıntılarından göstergeleri çıkarın ve analiz edin.

- **parse_details_field**  
  `Details` alanından anahtar/değer çiftlerini çıkarır.  
  Listelemeyi ve benzersiz toplamayı destekler.

- **extract_iocs**  
  `Details` ve `ExtraFieldInfo` alanlarından türe göre kategorilere ayrılmış **Tehlike Göstergelerini (IOC'ler)** çıkarır.

- **decode_powershell_commands**  
  Olaylarda bulunan Base64 ile kodlanmış PowerShell komutlarını çözer.
