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

נכניס בתכנית מחרוזת עם כתובת המייצגת את השרת:

<img width="427" height="182" alt="image" src="https://github.com/user-attachments/assets/df53ae1f-2e80-4c50-927a-160a7fb12391" />





