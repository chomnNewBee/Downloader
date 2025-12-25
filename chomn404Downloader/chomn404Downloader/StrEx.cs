namespace chomn404Downloader;

public static class StrEx
{
    public static bool IsValidString(this string str)
    {
        if (string.IsNullOrEmpty(str) || string.IsNullOrWhiteSpace(str))
            return false;
        return true;
    }
}