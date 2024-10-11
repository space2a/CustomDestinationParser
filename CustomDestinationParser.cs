using System.Text;

using Securify.ShellLink;

namespace space2a.CustomDestinationParser
{
    public static class CustomDestinationParser
    {
        public static JumpFileCategory[] Parse(string filePath, int fixRange = 12)
        {
            byte[] data = File.ReadAllBytes(filePath);

            //FILE HEADER

            byte[] referenceLnkGuid = new byte[] { 1, 20, 2, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70 }; //00021401-0000-0000-c000-000000000046

            int offset = 0;

            int formatVersion = BitConverter.ToInt32(data[offset..(offset += 4)]); //0, 4
            int numberOfCategories = BitConverter.ToInt32(data[offset..(offset += 4)]); //4, 8
            int unknown = BitConverter.ToInt32(data[offset..(offset += 4)]); //8, 12

            JumpFileCategory[] jumpFileCategories = new JumpFileCategory[numberOfCategories];

            //FILE CATEGORIES
            for (int c = 0; c < numberOfCategories; c++)
            {
                JumpFileCategory jumpFileCategory = new JumpFileCategory();
                jumpFileCategories[c] = jumpFileCategory;

                int categoryType = BitConverter.ToInt32(data[offset..(offset += 4)]);
                jumpFileCategory.JumpFileCategoryType = (JumpFileCategoryType)categoryType;

                if (jumpFileCategory.JumpFileCategoryType == JumpFileCategoryType.Custom || jumpFileCategory.JumpFileCategoryType == JumpFileCategoryType.UserTasks)
                {
                    if (jumpFileCategory.JumpFileCategoryType == JumpFileCategoryType.Custom)
                    {
                        ushort categoryNameLength = BitConverter.ToUInt16(data[offset..(offset += 2)]);
                        string categoryName = Encoding.Unicode.GetString(data[offset..(offset += categoryNameLength * 2)]);
                        jumpFileCategory.Name = categoryName;
                    }
                    else
                        jumpFileCategory.Name = "Tasks";

                    int entries = BitConverter.ToInt32(data[offset..(offset += 4)]);
                    jumpFileCategory.Entries = new JumpFileEntry[entries];

                    for (int e = 0; e < entries; e++)
                    {
                        JumpFileEntry jumpFileEntry = new JumpFileEntry();
                        jumpFileCategory.Entries[e] = jumpFileEntry;

                        if (referenceLnkGuid.SequenceEqual(data[offset..(offset + 16)]) == false)
                        {
                            //Fixing the offset
                            for (int i = -fixRange; i < fixRange; i++)
                            {
                                byte[] guidArray = data[(offset + i)..((offset + i) + 16)];
                                if (referenceLnkGuid.SequenceEqual(guidArray))
                                {
                                    offset = offset + i;
                                    break;
                                }
                            }
                        }

                        jumpFileEntry.Guid = new Guid(data[offset..(offset += 16)]);
                        jumpFileEntry.Shortcut = Shortcut.FromByteArray(data.Skip(offset).ToArray());

                        offset += jumpFileEntry.Shortcut.Size - (3);
                    }

                    if (offset >= data.Length || offset + 4 >= data.Length)
                        return jumpFileCategories;
                    if (BitConverter.ToInt32(data[offset..(offset + 4)]) != -1161823317) //should not be needed
                    {
                        //Fixing the offset
                        for (int i = -fixRange; i < fixRange; i++)
                        {
                            if (BitConverter.ToInt32(data[(offset + i)..((offset + i) + 4)]) == -1161823317)
                            {
                                offset = offset + i;
                                break;
                            }
                        }
                    }

                    jumpFileCategory.Signature = BitConverter.ToInt32(data[offset..(offset += 4)]).ToString("X");
                }
                else if (jumpFileCategory.JumpFileCategoryType == JumpFileCategoryType.Known)
                {
                    offset += 4;
                    // /!\ if you want the category identifier, comment the line above and uncomment the one below /!\
                    //JumpFileCategoryIdentifier identifier = (JumpFileCategoryIdentifier)BitConverter.ToInt32(data[offset..(offset += 4)]); 
                }
                else
                {
                    Console.WriteLine("Unsupported JumpFileCategoryType " + categoryType);
                }
            }

            return jumpFileCategories;
        }

        public class JumpFileCategory
        {
            public JumpFileCategoryType JumpFileCategoryType { get; internal set; }

            public string Name { get; internal set; }

            public JumpFileEntry[] Entries { get; internal set; }

            public string Signature { get; internal set; }

            public override string ToString()
            {
                return Name + " entries : " + Entries.Length;
            }
        }

        public class JumpFileEntry
        {
            public string Name
            {
                get
                {
                    try
                    {
                        if (Shortcut.StringData != null && !String.IsNullOrWhiteSpace(Shortcut.StringData.NameString)) return Shortcut.StringData.NameString;

                        return Shortcut.ExtraData.PropertyStoreDataBlock.PropertyStore[0].PropertyStorage[0].TypedPropertyValue.Value.ToString();
                    }
                    catch (Exception) { }
                    return null;
                }
            }

            public Guid Guid { get; internal set; }
            public Shortcut Shortcut { get; internal set; }
        }

        public enum JumpFileCategoryType : byte
        {
            Custom = 0,
            Known = 1,
            UserTasks = 2
        }

        public enum JumpFileCategoryIdentifier
        {
            UNKNOWN = 0,
            KDC_FREQUENT = 1,
            KDC_RECENT = 2
        }
    }
}
