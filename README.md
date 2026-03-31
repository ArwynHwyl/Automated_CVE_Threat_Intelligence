Architecture & Tech Stack
Data Source: NVD API  
Database: Microsoft Dataverse  
Pipeline & API Gateway: Power Automate (ใช้เป็น HTTP Trigger)  
Backend Proxy: Golang (ใช้จัดการ CORS และดึงข้อมูล เพราะว่าพยายามดึงจากfrontendตรงๆแล้วแต่ว่า flow ของHTTP มันกันไม่ให้ส่งheaderอะไรให้เลย เลยต้องใช้ Go Proxy)  
Frontend: HTML, CSS, JS  
  
Problem Encounter and mitigation:
IT ของ CMU เขาบล็อคไม่ให้นักศึกษาสร้างApp register ใน Entra ID ระดับ Tenant ทำให้การเรียกใช้Dataverseแบบปลอดภัยมีปัญหา ผมเลยแก้ด้วยการใช้ Power Automate มุดสร้าง API Gateway ดึงข้อมูลจาก Dataverse ออกมาแทน
Data Duplicate แก้ด้วย Flow Logic ดักข้อมูลซ้ำก่อนบันทึกลง Database
Mapping JSON Instructor จริงๆในPower appเขาก็มีAuto generateตามที่เราก็อปไปว่างอยู่แล้วส่วนนี้ก็เลยไม่เป็นปัญหามากครับ

