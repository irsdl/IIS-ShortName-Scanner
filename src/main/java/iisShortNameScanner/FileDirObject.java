/*
 * // IIS Shortname Scanner
 * // Released as open source by Soroush Dalili (@irsdl)
 * // Researched & developed by Soroush Dalili (@irsdl)
 * // Project link: https://github.com/irsdl/IIS-ShortName-Scanner
 * // Released under AGPL see LICENSE for more information
 */

package iisShortNameScanner;

/* Currently not used
 * This will be completed gradually
 *
 * */
public class FileDirObject {
    private Boolean isDirectory;
    private String fullName;
    //	private String name;
//	private String extension;
    private String parentPath;
    private String baseTarget;
    private String possibleName;
    private String possibleExtension;
    private String actualNameVerified;
    private String verificationMethod;

    public FileDirObject(Boolean isDirectory, String name, String parentPath,
                         String baseTarget) {
        super();
        this.isDirectory = isDirectory;
        this.fullName = name;
        this.parentPath = parentPath;
        this.baseTarget = baseTarget;
    }

    public Boolean getIsDirectory() {
        return isDirectory;
    }

    public void setIsDirectory(Boolean isDirectory) {
        this.isDirectory = isDirectory;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getParentPath() {
        return parentPath;
    }

    public void setParentPath(String parentPath) {
        this.parentPath = parentPath;
    }

    public String getBaseTarget() {
        return baseTarget;
    }

    public void setBaseTarget(String baseTarget) {
        this.baseTarget = baseTarget;
    }

    public String getPossibleName() {
        String possibleNameResult = "";
        if (possibleName.isEmpty()) {
            if (fullName.lastIndexOf("~") < 6) {
                possibleNameResult = fullName.substring(0, fullName.lastIndexOf("~"));
            }
        } else
            possibleNameResult = possibleName;
        return possibleNameResult;
    }

    public void setPossibleName(String possibleName) {
        this.possibleName = possibleName;
    }

    public String getPossibleExtension() {
        String possibleExtentionResult = "";

        if (possibleExtension.isEmpty()) {
            if (fullName.length() - fullName.lastIndexOf(".") <= 3)
                possibleExtentionResult = getExtension();
        } else {
            possibleExtentionResult = possibleExtension;
        }

        return possibleExtentionResult;
    }

    public void setPossibleExtension(String possibleExtension) {
        this.possibleExtension = possibleExtension;
    }

    public String getActualNameVerified() {
        return actualNameVerified;
    }

    public void setActualNameVerified(String actualNameVerified) {
        this.actualNameVerified = actualNameVerified;
    }

    public String getVerificationMethod() {
        return verificationMethod;
    }

    public void setVerificationMethod(String verificationMethod) {
        this.verificationMethod = verificationMethod;
    }

    public String getName() {
        return fullName.substring(0, fullName.lastIndexOf("."));
    }

    public String getExtension() {

        return fullName.substring(fullName.lastIndexOf("."));
    }

    @Override
    public String toString() {
        return "FileDirObject [name=" + fullName + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((isDirectory == null) ? 0 : isDirectory.hashCode());
        result = prime * result + ((fullName == null) ? 0 : fullName.hashCode());
        result = prime * result
                + ((parentPath == null) ? 0 : parentPath.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        FileDirObject other = (FileDirObject) obj;
        if (isDirectory == null) {
            if (other.isDirectory != null)
                return false;
        } else if (!isDirectory.equals(other.isDirectory))
            return false;
        if (fullName == null) {
            if (other.fullName != null)
                return false;
        } else if (!fullName.equals(other.fullName))
            return false;
        if (parentPath == null) {
            if (other.parentPath != null)
                return false;
        } else if (!parentPath.equals(other.parentPath))
            return false;
        return true;
    }

}
