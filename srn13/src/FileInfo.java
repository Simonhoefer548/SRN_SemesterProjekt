
public class FileInfo {
	private String filename;
	private String filepath;
	private String creator;
	
	
	public FileInfo(String filename, String filepath, String creator) {
		super();
		this.filename = filename;
		this.filepath = filepath;
		this.creator = creator;
	}
	public String getFilename() {
		return filename;
	}
	public void setFilename(String filename) {
		this.filename = filename;
	}
	public String getFilepath() {
		return filepath;
	}
	public void setFilepath(String filepath) {
		this.filepath = filepath;
	}
	public String getCreator() {
		return creator;
	}
	public void setCreator(String creator) {
		this.creator = creator;
	}
	
	

}
