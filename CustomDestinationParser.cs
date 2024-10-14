using System.Text;

using Securify.ShellLink;

namespace space2a
{
    public static class CustomDestinationParser
    {
        private static byte[] referenceLnkGuid = new byte[] { 1, 20, 2, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70 }; //00021401-0000-0000-c000-000000000046
        private static int decimalSignature = -1161823317; //BABFFBAB

        public static JumpFileCategory[] Parse(string filePath, int fixRange = 12)
        {
            byte[] data = File.ReadAllBytes(filePath);


            int offset = 0;

            //FILE HEADER
            int formatVersion = BitConverter.ToInt32(data[offset..(offset += 4)]); //0, 4
            int numberOfCategories = BitConverter.ToInt32(data[offset..(offset += 4)]); //4, 8
            int unknown = BitConverter.ToInt32(data[offset..(offset += 4)]); //8, 12

            JumpFileCategory[] jumpFileCategories = new JumpFileCategory[numberOfCategories];

            //FILE CATEGORIES
            for (int c = 0; c < numberOfCategories; c++)
            {
                try
                {
                    JumpFileCategory jumpFileCategory = new JumpFileCategory();
                    jumpFileCategories[c] = jumpFileCategory;

                    int categoryType = BitConverter.ToInt32(data[offset..(offset += 4)]);
                    jumpFileCategory.JumpFileCategoryType = (JumpFileCategoryType)categoryType;

                    int entries = -1;

                    if (jumpFileCategory.JumpFileCategoryType == JumpFileCategoryType.Custom)                                                           //CUSTOM 0 
                    {
                        ushort categoryNameLength = BitConverter.ToUInt16(data[offset..(offset += 2)]);
                        jumpFileCategory.Name = Encoding.Unicode.GetString(data[offset..(offset += categoryNameLength * 2)]);
                    }
                    else if (jumpFileCategory.JumpFileCategoryType == JumpFileCategoryType.Known)                                                       //KNOWN 1
                    {
                        JumpFileCategoryIdentifier identifier = (JumpFileCategoryIdentifier)BitConverter.ToInt32(data[offset..(offset += 4)]);

                        if ((int)identifier <= 0 && BitConverter.ToInt32(data[offset..(offset + 4)]) == decimalSignature)
                        {
                            int unknown2 = BitConverter.ToInt32(data[(offset += 4)..(offset += 4)]);

                            ushort categoryNameLength = BitConverter.ToUInt16(data[offset..(offset += 2)]);
                            jumpFileCategory.Name = Encoding.Unicode.GetString(data[offset..(offset += categoryNameLength * 2)]);

                            entries = BitConverter.ToUInt16(data[offset..(offset += 2)]);
                        }
                        else continue; //cannot read it
                    }
                    else if (jumpFileCategory.JumpFileCategoryType == JumpFileCategoryType.UserTasks)                                                   //USERTASK 2
                        jumpFileCategory.Name = "Tasks";
                    else                                                                                                                                //UNKNOWN
                        Console.WriteLine($"Unknown category ({categoryType})");

                    if (entries == -1)
                        entries = BitConverter.ToInt32(data[offset..(offset += 4)]);

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

                    if (BitConverter.ToInt32(data[offset..(offset + 4)]) != decimalSignature) //should not be needed
                    {
                        //Fixing the offset
                        for (int i = -fixRange; i < fixRange; i++)
                        {
                            if (BitConverter.ToInt32(data[(offset + i)..((offset + i) + 4)]) == decimalSignature)
                            {
                                offset = offset + i;
                                break;
                            }
                        }
                    }

                    jumpFileCategory.Signature = BitConverter.ToInt32(data[offset..(offset += 4)]).ToString("X");
                }
                catch (Exception)
                {

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
                    try //ugly but works
                    {
                        if (Shortcut.StringData != null && !String.IsNullOrWhiteSpace(Shortcut.StringData.NameString)) return Shortcut.StringData.NameString;

                        for (int i = 0; i < Shortcut.ExtraData.PropertyStoreDataBlock.PropertyStore.Count; i++)
                        {
                            try
                            {
                                for (int l = 0; l < Shortcut.ExtraData.PropertyStoreDataBlock.PropertyStore[i].PropertyStorage.Count; l++)
                                {
                                    string n = Shortcut.ExtraData.PropertyStoreDataBlock.PropertyStore[i].PropertyStorage[l].TypedPropertyValue.Value.ToString();
                                    if (!String.IsNullOrWhiteSpace(n)) return n;
                                }
                            }
                            catch (Exception) { }
                        }
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
