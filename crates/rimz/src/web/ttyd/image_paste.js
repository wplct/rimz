const RIMZ_IMAGE_UPLOAD_PATH="/__rimz/upload/image";

// 将服务端生成的绝对路径安全地放进当前 shell/Agent 输入。
const shellQuoteImagePath=path=>`'${path.replaceAll("'","'\"'\"'")}'`;

// 捕获剪贴板图片并用返回路径替代二进制粘贴。
const installImagePaste=(term,fetchImage=window.fetch.bind(window))=>{
  const pasteImage=async event=>{
    const items=Array.from(event.clipboardData&&event.clipboardData.items||[]);
    const item=items.find(candidate=>candidate.kind==="file"&&candidate.type.startsWith("image/"));
    if(!item)return;
    const image=item.getAsFile();
    if(!image)return;
    event.preventDefault();
    event.stopPropagation();
    try{
      const response=await fetchImage(RIMZ_IMAGE_UPLOAD_PATH,{
        method:"POST",
        credentials:"same-origin",
        headers:{
          "Content-Type":image.type||"application/octet-stream",
          "X-RimZ-Upload":"image",
        },
        body:image,
      });
      if(!response.ok)throw new Error(`upload returned HTTP ${response.status}`);
      const payload=await response.json();
      if(!payload||typeof payload.path!=="string"||!/^\/[^\0\r\n]+$/.test(payload.path)){
        throw new Error("upload returned an invalid path");
      }
      term.paste(shellQuoteImagePath(payload.path));
    }catch(error){
      console.error("RimZ image paste failed",error);
    }
  };
  term.element.addEventListener("paste",pasteImage,true);
  return ()=>term.element.removeEventListener("paste",pasteImage,true);
};
