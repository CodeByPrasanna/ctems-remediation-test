// Generate weekly reports

function generateReport() {
  DriveApp.getFiles();

  SpreadsheetApp.openById("123");
}
