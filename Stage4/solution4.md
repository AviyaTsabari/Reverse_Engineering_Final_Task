מטרת השינוי היא לגרום לתוכנית לשלוח הודעת HTTP לשרת מקומי שרץ בכתובת 127.0.0.1 ובפורט 80, ולאחר מכן להמשיך את הריצה הרגילה שלה.

נפתח תיקייה במחשב ושם נכתוב קוד פייתון שמייצר שרת (מצ"ב בתקייה), הפעלנו את השרת דרך CMD:

<img width="822" height="430" alt="image" src="https://github.com/user-attachments/assets/387909bd-84b3-4b83-b06b-a1089eb44612" />

בדיקה שהשרת עובד:

<img width="532" height="167" alt="image" src="https://github.com/user-attachments/assets/77612627-3daf-4565-9df9-3b2c31520135" />

בדיקה שהשרת מקבל בקשות:
<img width="697" height="97" alt="image" src="https://github.com/user-attachments/assets/8a3dacf0-6fce-4b91-a316-3aca91ce6d19" />

הכל תקין אפשר להתקדם!

נבדוק מIDA האם המשחק גבר משתמש בספריות רשת, נחפש באימפורט ייבוא כמו WININET.dll ,WS2_32.dll, WINHTTP.dll, InternetOpenA,HttpSendRequestA, socket וכולי.

קושי ראשון - אין ייבוא למשחק של ספרייה העוסקת ברשת ונצטרך לעשות זאת בעצמנו.

קיים יבוא של LoadLibraryA ,GetProcAddress אז נשתמש בהן כדי לייבא בזמן ריצה את wininet.dll.

קושי שני - אין מספיק מקום ריק לכתוב קוד חדש אז נצטרך ליצור section חדש באמצעות CFF וניתן לו הרשאות RWE.

כמו בפעם הקודמת הכתובת הוירטואלית של הסקשן היא 20000 והimagebase של הקובץ הוא 1000000 אז הסקשן מתחיל ב1020000.

על מנת לקרוא לפונקציות המצא את הכתובת שלהן:  01001094 GetProcAddress 0100109C LoadLibraryA

כעת נפתח את IDA בתחילת הסקשן החדש 1020000 ונכתוב שם את הקוד הבא:

    pushad
    
    push    1020100h
    
    call    dword ptr [100109Ch]
    
    popad
    
    push    70h
    
    push    1001390h
    
    jmp     1003E28h//חזרה לפקודה השלישית

עשינו שינוי בCFF שכתובת נקודת הפתיחה תהיה 20000.

הבעיה שמצאנו היא שהפקודה ב־01020006 לא פונה לכתובת הנכונה של LoadLibraryA. היא הייתה אמורה לקרוא את מצביע הפונקציה מתוך: 0100109C

אבל בפועל קוד המכונה שנוצר מפנה אל: 01FE109C. לכן המעבד ניסה לקרוא כתובת זיכרון שאינה קיימת וקיבל שגיאת: The memory could not be read.
אז אחרי הרבה הסתבכות עם חישוב הכתובות שלא רלוונטי להוסיף פה החלטתי לטעון את הספרייה באמצעות CFF.

פתחתי את הקובץ שוב בCFF ותחת הלשונית import added לחצתי add והוספתי את C:\Windows\SysWOW64\wininet.dll עכשיו עשיתי ייבוא לפונקציות האלו:

InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestA, InternetCloseHandle.

עכשיו אני רואה בIDA שהפונקציות נמצאות:

<img width="478" height="127" alt="image" src="https://github.com/user-attachments/assets/4cdf53b4-797c-481e-b402-770b91c654ae" />

אבל כעת אני רואה שהכל נכתב בסקשן 20000, אז בשביל הקוד החדש אני רוצה סקשן נוסף לכתוב בו, אז ניכנס שוב לCFF ונוסיף והכתובת הוירטואלית של הסקשן של הקוד היא 22000.

נכניס בתכנית מחרוזות בהתאם למה שאנחנו רוצים (סוג הבקשה ומחרוזות של הודעה):

<img width="842" height="240" alt="image" src="https://github.com/user-attachments/assets/ae3622db-2eee-4f97-8e51-5b61b750c89b" />

בכניסה לתוכנית, כפי שעשינו בחלק ג נדרוס את שתי ההוראות הראשונה על ידי פקודת JMP לסקשן הקוד 1022000 (+ שתי פקודות Nop לאיזון הבתים) ובקוד שלנו נסיים עם שתי הפקודות האלו ונקפוץ בחזרה לפקודה השלישית המקורית.

נכתוב את הקוד הבא ונסביר:
    
    pusha
    
    ; ============================================================
    
                                                                                                                                                ; יצירת Internet Session
    
    ; InternetOpenA("Test", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0)
    
    ; ============================================================
    
    push    0
    
    push    0
    
    push    0
    
    push    1
    
    push    offset aTest
    
    call    ds:InternetOpenA
    
                                                                                                                                                                                                                                                                                                            ; שמירת ה-handle של ה-session
    
    mov     ebx, eax
    
    
    ; ============================================================
                                                                                          
                                                                                                                                                    ; התחברות לשרת המקומי
    ; InternetConnectA(hInternet, "127.0.0.1", 80, NULL, NULL,
    ;                  INTERNET_SERVICE_HTTP, 0, 0)
    
    ; ============================================================
    
    push    0
    
    push    0
    
    push    3
    
    push    0
    
    push    0
    
    push    50h                 ; פורט 80
    
    push    offset a127001      ; "127.0.0.1"
    
    push    ebx
    
    call    ds:InternetConnectA
    
                                                                                                                                                                                                                                                                                                                ; שמירת ה-handle של החיבור
    
    mov     esi, eax
    
    
    ; ============================================================
    
                                                                                                                                                                                                                                                                                                            ; יצירת בקשת HTTP מסוג POST
    
    ; HttpOpenRequestA(...)
    
    ; ============================================================
    
    push    0
    
    push    0
    
    push    0
    
    push    0
    
    push    0
    
    push    offset aMessage     ; "/message"
    
    push    offset aPost        ; "POST"
    
    push    esi
    
    call    ds:HttpOpenRequestA
    
                                                                                                                                                                                                                                                                                                                ; שמירת ה-handle של הבקשה
    
    mov     edi, eax
    
    
    ; ============================================================
                                                                                                                                                                                                                                                                                                                    ; שליחת הבקשה לשרת
    
    ; HttpSendRequestA(...)
    
    ; ============================================================
    
    push    10h
    
    push    offset aHelloFromPatch     ; "Hello from patch"
    
    push    0
    
    push    0
    
    push    edi 
    
    call    ds:HttpSendRequestA
    
    ; ============================================================
    
                                                                                                                                                                                                                                                                                                                        ; שחרור כל ה-handles
    
    ; ============================================================
    
                                                                                                                                                                                                                                                                                                                        ; סגירת ה-request
    
    push    edi
    
    call    ds:InternetCloseHandle
    
                                                                                                                                                                                                                                                                                                                            ; סגירת החיבור
    
    push    esi
    
    call    ds:InternetCloseHandle
    
                                                                                                                                                                                                                                                                                                                        ; סגירת ה-session
    
    push    ebx
    
    call    ds:InternetCloseHandle
    
    ; ============================================================
    
                                                                                                                                     ; שחזור האוגרים וחזרה לתוכנית המקורית
    
    ; ============================================================
    
    popa
    
    push    70h
    
    push    offset stru_1001390
    
    jmp     loc_1003E28

הסבר

שמירת האוגרים:

בתחילת הקוד ביצענו pusha, כדי לשמור את כל האוגרים של המשחק ולא לפגוע בפעולתו.
                                                                                                                                                                    פתיחת Session לאינטרנט:

קראנו ל־InternetOpenA, שיצרה Session של WinINet והחזירה handle, אותו שמרנו ב־EBX.

התחברות לשרת המקומי:
                                                                                                                                                                    קראנו ל־InternetConnectA עם הכתובת 127.0.0.1 ופורט 80.
                                                                                                                                                                    הפונקציה יצרה חיבור לשרת המקומי והחזירה handle, אותו שמרנו ב־ESI.

יצירת בקשת HTTP :
                                                                                                                                                                    קראנו ל־HttpOpenRequestA כדי ליצור בקשת HTTP מסוג POST לנתיב /message.
                                                                                                                                                                    הפונקציה החזירה handle לבקשה, אותו שמרנו ב־EDI.
                                                                                                                                                                    שליחת ההודעה:
                                                                                                                                                                    קראנו ל־HttpSendRequestA, ששלחה לשרת את המחרוזת "Hello from patch".

שחרור משאבים:

סגרנו את שלושת ה־handles (EDI, ESI, EBX) באמצעות InternetCloseHandle, כדי למנוע דליפת משאבים.
                                                                                                                                                                    חזרה לתוכנית המקורית:
                                                                                                                                                                    ביצענו popa כדי לשחזר את כל האוגרים למצבם המקורי.
                                                                                                                                                                    קפצנו בחזרה לנקודת ההמשך של המשחק (jmp loc_1003E28), כך שהתוכנית ממשיכה לרוץ כאילו לא בוצעה שום התערבות.


כעת נותר להפעיל את המשחק ולראות מה קורה בשרת:

<img width="683" height="121" alt="צילום מסך 2026-07-14 222826" src="https://github.com/user-attachments/assets/4010186e-c40b-44dc-9810-f78d69739fcd" />

רואים שנשלחה ההודעה בהצלחה: Hello from patch.

היה לא פשוט בכלל ודרש לחפש פונקציות חדשות שעובדות עם השרת וללמוד איך לייבא אותן באמצעות CFF ולפתוח מקום חדש (סקשן) ריק על מנת שנוכל "להזריק את הקוד" אבל ברוך השם הצלחתי וזה מאוד מספק!
