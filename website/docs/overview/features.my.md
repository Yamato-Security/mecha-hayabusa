# လုပ်ဆောင်ချက်များ

## Dataset Operations

ပိုင်းခြားစိတ်ဖြာမှုအတွက် အသုံးပြုသော datasets များကို စီမံခန့်ခွဲပါ။

- **get_dataset_status**  
  လက်ရှိ load လုပ်ထားသော dataset ၏ အခြေအနေကို ထုတ်ယူပါ။

- **list_datasets**  
  ပိုင်းခြားစိတ်ဖြာမှုအတွက် ရရှိနိုင်သော CSV datasets များကို စာရင်းပြုစုပါ။  
  Pagination ကို ပံ့ပိုးသည်။

- **switch_dataset**  
  လက်ရှိ active ပိုင်းခြားစိတ်ဖြာမှု dataset ကို သတ်မှတ်ထားသော CSV ဖိုင်သို့ ပြောင်းလဲပါ။

- **unload_dataset**  
  လက်ရှိ `logs` table ကို unload လုပ်ပါ။

- **dataset_profile**  
  dataset ၏ အကျဉ်းချုပ်ကို ထုတ်ယူပါ၊ အောက်ပါတို့ ပါဝင်သည်−
  - စုစုပေါင်း event အရေအတွက်
  - အချိန်အပိုင်းအခြား
  - ထိပ်တန်း ခေတ်စားမှုများ

  Pagination ကို ပံ့ပိုးသည်။

---

## Query & Search

Log data ကို ရှာဖွေ၍ query ပြုလုပ်ပါ။

- **run_sql**  
  `logs` table ကို ဆန့်ကျင်၍ read-only `SELECT` query တစ်ခုကို လုပ်ဆောင်ပါ။  
  ပါဝင်ပြီးသား လုံခြုံရေး ကန့်သတ်ချက်များ ပါရှိသည်။

- **search_all_fields**  
  columns အားလုံး သို့မဟုတ် သတ်မှတ်ထားသော columns များတစ်လျှောက် keyword ရှာဖွေမှုများ ပြုလုပ်ပါ။  
  Pagination ကို ပံ့ပိုးသည်။

- **get_event_detail**  
  ချဲ့ထွင်ထားသော `Field / Value` ဖော်မတ်ဖြင့် event တစ်ခုကို ထုတ်ယူပါ။  
  `RecordID` သို့မဟုတ် query အခြေအနေများဖြင့် ရှာဖွေခြင်းကို ပံ့ပိုးသည်။

---

## Timeline & Analytics

တိုက်ခိုက်မှု လှုပ်ရှားမှုနှင့် event timelines များကို ပိုင်းခြားစိတ်ဖြာပါ။

- **analyze_mitre_tactics**  
  **MITRE ATT&CK tactics** အလိုက် အုပ်စုဖွဲ့ထားသော တိုက်ခိုက်မှု အဆင့်များ၏ အချိန်အလိုက် ပိုင်းခြားစိတ်ဖြာမှုကို ပြုလုပ်ပါ။

- **analyze_host_timeline**  
  သီးခြား host တစ်ခုအတွက် အချိန်အလိုက် events များကို ထုတ်ယူပါ။  
  **compromise chain tracking** အတွက် အသုံးဝင်သည်။

- **correlate_lateral_movement**  
  သတ်မှတ်ထားသော အချိန်ကာလအတွင်း hosts များကြား lateral movement လှုပ်ရှားမှုကို ဆက်စပ်ပါ။

- **summarize_events**  
  သတ်မှတ်ထားသော field တစ်ခုအလိုက် log events များကို စုစည်းပါ။

- **summarize_by_time_window**  
  အချိန်အပိုင်းအခြားအလိုက် events များကို ရေတွက်ပါ−
  - `1h`
  - `3h`
  - `6h`
  - `12h`
  - `1d`

- **analyze_rule_titles**  
  ရွေးချယ်နိုင်သော filtering အခြေအနေများဖြင့် `RuleTitle` ဖြစ်ပေါ်မှုများ၏ ကြိမ်နှုန်းကို စုစည်းပါ။

---

## Detail & IOC Analysis

Log အသေးစိတ်အချက်အလက်များမှ indicators များကို ထုတ်ယူ၍ ပိုင်းခြားစိတ်ဖြာပါ။

- **parse_details_field**  
  `Details` field မှ key/value အတွဲများကို ထုတ်ယူပါ။  
  စာရင်းပြုစုခြင်းနှင့် unique စုစည်းခြင်းကို ပံ့ပိုးသည်။

- **extract_iocs**  
  `Details` နှင့် `ExtraFieldInfo` များမှ **Indicators of Compromise (IOCs)** များကို အမျိုးအစားအလိုက် ခွဲခြားသတ်မှတ်၍ ထုတ်ယူပါ။

- **decode_powershell_commands**  
  events များတွင် တွေ့ရှိသော Base64-encoded PowerShell commands များကို decode လုပ်ပါ။
