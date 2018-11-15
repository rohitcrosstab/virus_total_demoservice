package talent_cache;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import com.sun.jersey.core.header.FormDataContentDisposition;
import com.sun.jersey.multipart.FormDataParam;

@Path("/hello")
public class talent_cache {
	

	String filePaths = new File("test_file").getAbsolutePath();



	@POST
	@Path("/virus_scan")

	@Produces({ MediaType.TEXT_HTML, MediaType.MULTIPART_FORM_DATA, MediaType.APPLICATION_JSON,
			MediaType.APPLICATION_XML, MediaType.TEXT_HTML })

	@Consumes({ MediaType.MULTIPART_FORM_DATA, MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML,
			MediaType.TEXT_HTML })
	public String virus_scan(@FormDataParam("file") InputStream fileInputStream,

			@FormDataParam("file") FormDataContentDisposition fileInputDetails) {

		try {

			System.out.println(fileInputDetails.getFileName());
			writeToFile(fileInputStream, fileInputDetails.getFileName());
			VirusTotalConfig.getConfigInstance()
					.setVirusTotalAPIKey("7fcfb1d868f64bf13bd89815cc4075a01b7698d5c1637d3947d41bea8965c6a6");
			VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

			ScanInfo scanInformation = virusTotalRef
					.scanFile(new File(filePaths + "/" + fileInputDetails.getFileName()));
			String resource = scanInformation.getResource();
			FileScanReport report = virusTotalRef.getScanReport(resource);
			/*System.out.println("___SCAN INFORMATION___");
			System.out.println("MD5 :\t" + scanInformation.getMd5());
			System.out.println("Perma Link :\t" + scanInformation.getPermalink());
			System.out.println("Resource :\t" + scanInformation.getResource());
			System.out.println("Scan Date :\t" + scanInformation.getScanDate());
			System.out.println("Scan Id :\t" + scanInformation.getScanId());
			System.out.println("SHA1 :\t" + scanInformation.getSha1());
			System.out.println("SHA256 :\t" + scanInformation.getSha256());
			System.out.println("Verbose Msg :\t" + scanInformation.getVerboseMessage());
			System.out.println("Response Code :\t" + scanInformation.getResponseCode());
			System.out.println("done.");

			System.out.println("MD5 :\t" + report.getMd5());
			System.out.println("Perma link :\t" + report.getPermalink());
			System.out.println("Resourve :\t" + report.getResource());
			System.out.println("Scan Date :\t" + report.getScanDate());
			System.out.println("Scan Id :\t" + report.getScanId());
			System.out.println("SHA1 :\t" + report.getSha1());
			System.out.println("SHA256 :\t" + report.getSha256());
			System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
			System.out.println("Response Code :\t" + report.getResponseCode());
			System.out.println("Positives :\t" + report.getPositives());
			System.out.println("Total :\t" + report.getTotal());*/

			Map<String, VirusScanInfo> scans = report.getScans();
			for (String key : scans.keySet()) {
				VirusScanInfo virusInfo = scans.get(key);
				System.out.println("Scanner : " + key);
				System.out.println("\t\t Resut : " + virusInfo.getResult());
				System.out.println("\t\t Update : " + virusInfo.getUpdate());
				System.out.println("\t\t Version :" + virusInfo.getVersion());
			}

		} catch (APIKeyNotFoundException ex) {
			System.err.println("API Key not found! " + ex.getMessage());
		} catch (UnsupportedEncodingException ex) {
			System.err.println("Unsupported Encoding Format!" + ex.getMessage());
		} catch (UnauthorizedAccessException ex) {
			System.err.println("Invalid API Key " + ex.getMessage());
		} catch (Exception ex) {
			System.err.println("Something Bad Happened! " + ex.getMessage());
		}
		delete_file(fileInputDetails.getFileName());

		return null;
	}

	private void delete_file(String filePath_del) {
		File file = new File(filePaths + "/" + filePath_del);
		file.delete();
		System.out.println("File Deleted");

	}

	// save uploaded file to new location
	private void writeToFile(InputStream uploadedInputStream, String filePath) throws Exception {
		OutputStream out = new FileOutputStream(new File(filePaths + "/" + filePath));
		int read = 0;
		byte[] bytes = new byte[1024];

		out = new FileOutputStream(new File(filePaths + "/" + filePath));
		while ((read = uploadedInputStream.read(bytes)) != -1) {
			out.write(bytes, 0, read);
		}

		out.flush();
		out.close();
	}


}