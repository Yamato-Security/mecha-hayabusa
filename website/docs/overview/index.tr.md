# Hakkında

**Mecha Hayabusa**, Windows olay günlüğü analiz aracı **Hayabusa**'yı **Model Context Protocol (MCP)** aracılığıyla büyük dil modellerine (LLM) bağlayarak doğal dil odaklı dijital adli bilişim ve tehdit avcılığını mümkün kılar. Analistler, MITRE ATT&CK taktik analizi, IOC çıkarımı, yanal hareket korelasyonu, PowerShell çözümü ve ana bilgisayar merkezli zaman çizelgesi analizi gibi yeteneklerle CSV tabanlı Windows olay günlüğü veri kümelerini inceleyebilir.

Hayabusa CSV zaman çizelgeleri otomatik olarak yerel bir **DuckDB** veritabanına dönüştürülür ve LLM'lerin büyük günlük veri kümeleri üzerinde hızlı, yapılandırılmış analiz gerçekleştirmesine olanak tanır. Sistem; veri kümesi değiştirme ve profil oluşturma, salt okunur SQL yürütme, alanlar arası arama, kural başlığı toplama, zaman penceresi özetleme, ana bilgisayar zaman çizelgesi analizi, `Details` alanı ayrıştırma, IOC çıkarımı, Base64 ile kodlanmış PowerShell çözümü ve yanal hareket korelasyonu dahil olmak üzere yetenekler sağlar.

Mecha Hayabusa ayrıca, DFIR iş akışını standartlaştıran ve **Japonca veya İngilizce** dillerinde yapılandırılmış olay raporu oluşturmayı destekleyen özel bir **inceleme becerisi** içerir.

Mecha Hayabusa'nın temel yeniliği, bir LLM'nin basit bir arama arayüzü olarak hareket etmek yerine **MCP aracılığıyla yapılandırılmış bir DFIR inceleme iş akışı** yürütmesini mümkün kılmasıdır. Bu yaklaşım, veri kümesi triyajı ve hipotez geliştirmeden saldırı aşaması analizine, ana bilgisayar düzeyinde incelemeye, yanal hareket korelasyonuna ve nihai rapor oluşturmaya kadar tüm inceleme yaşam döngüsünü desteklerken, olaya müdahale ekipleri için tutarlılığı ve verimliliği artırır.
